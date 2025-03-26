package runner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/g0ldencybersec/gungnir/pkg/utils"
	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/x509"

	"github.com/g0ldencybersec/gungnir/pkg/types"
)

// Global variables
var (
	logListUrl          = "https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
	defaultRateLimitMap = map[string]time.Duration{
		"Google":        time.Millisecond * 1,
		"Sectigo":       time.Second * 4,
		"Let's Encrypt": time.Second * 1,
		"DigiCert":      time.Second * 1,
		"TrustAsia":     time.Second * 1,
	}
)

type Runner struct {
	logClients     []types.CtLog
	rootDomains    map[string]bool
	rateLimitMap   map[string]time.Duration
	entryTasksChan chan types.EntryTask
	restartChan    chan struct{}
	domainsChan    chan<- string
}

/*
	runner, err := runner.NewRunner(<pass subdomain chan>)
	if err != nil {
		log.Fatalf("Error creating runner: %v", err)
	}

	runner.Run()

*/

func NewRunner(domainsChan chan<- string, rootDomains []string) (*Runner, error) {
	runner := &Runner{
		rootDomains: make(map[string]bool),
		restartChan: make(chan struct{}),
		domainsChan: domainsChan,
	}

	for _, rd := range rootDomains {
		runner.rootDomains[rd] = true
	}

	var err error
	runner.logClients, err = utils.PopulateLogs(logListUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to populate logs: %v", err)
	}

	runner.entryTasksChan = make(chan types.EntryTask, len(runner.logClients)*100)
	runner.rateLimitMap = defaultRateLimitMap

	return runner, nil
}

func (r *Runner) AddRootDomain(rootDomain string) {
	r.rootDomains[rootDomain] = true
	r.restartChan <- struct{}{} // each time a root domain is added we need to restart the scan
}

func (r *Runner) RemoveRootDomain(rootDomain string) {
	delete(r.rootDomains, rootDomain)
	r.restartChan <- struct{}{} // each time a root domain is removed we need to restart the scan
}

func (r *Runner) Run() {
	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		for {
			select {
			case <-signals:
				fmt.Fprintf(os.Stderr, "Shutdown signal received\n")
				cancel()
				return
			case <-r.restartChan:
				fmt.Fprintf(os.Stderr, "Restarting scan due to file update\n")
				cancel()
				ctx, cancel = context.WithCancel(context.Background())
				go r.startScan(ctx, &wg)
			}
		}
	}()

	r.startScan(ctx, &wg)

	wg.Wait()
	close(r.entryTasksChan)

	fmt.Fprintf(os.Stderr, "Gracefully shutdown all routines\n")
}

func (r *Runner) startScan(ctx context.Context, wg *sync.WaitGroup) {
	// Start entry workers
	for i := 0; i < len(r.logClients); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.entryWorker(ctx)
		}()
	}

	// Start scanning logs
	for _, ctl := range r.logClients {
		wg.Add(1)
		go r.scanLog(ctx, ctl, wg)
	}
}

func (r *Runner) entryWorker(ctx context.Context) {
	for {
		select {
		case task, ok := <-r.entryTasksChan:
			if !ok {
				return // Channel closed, terminate the goroutine
			}
			r.processEntries(task.Entries, task.Index)
		case <-ctx.Done():
			return // Context cancelled, terminate the goroutine
		}
	}
}

func (r *Runner) scanLog(ctx context.Context, ctl types.CtLog, wg *sync.WaitGroup) {
	defer wg.Done()

	tickerDuration := time.Second // Default duration
	for key := range r.rateLimitMap {
		if strings.Contains(ctl.Name, key) {
			tickerDuration = r.rateLimitMap[key]
			break
		}
	}

	// Is this a google log?
	IsGoogleLog := strings.Contains(ctl.Name, "Google")

	ticker := time.NewTicker(tickerDuration)
	defer ticker.Stop()

	var start, end int64
	var err error

	// Retry fetching the initial STH with context-aware back-off
	for retries := 0; retries < 3; retries++ {
		if err = r.fetchAndUpdateSTH(ctx, ctl, &end); err != nil {
			/*if r.options.Verbose {
				fmt.Fprintf(os.Stderr, "Retry %d: Failed to get initial STH for log %s: %v\n", retries+1, ctl.Client.BaseURI(), err)
			}*/
			select {
			case <-ctx.Done():
				return
			case <-time.After(60 * time.Second): // Wait with context awareness
				continue
			}
		}
		break
	}

	start = end - 20

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if start >= end {
				if err = r.fetchAndUpdateSTH(ctx, ctl, &end); err != nil {
					/*if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "Failed to update STH: %v\n", err)
					}*/
					select {
					case <-ctx.Done():
						return
					case <-time.After(60 * time.Second): // Wait with context awareness
					}
					continue
				}
				/*if r.options.Debug {
					if end-start > 25 {
						fmt.Fprintf(os.Stderr, "%s is behind by: %d\n", ctl.Name, end-start)
					}
				}*/
				continue
			}

			// Work with google logs
			if IsGoogleLog {
				for start < end {
					batchEnd := start + 32
					if batchEnd > end {
						batchEnd = end
					}
					entries, err := ctl.Client.GetRawEntries(ctx, start, batchEnd)
					if err != nil {
						/*if r.options.Verbose {
							fmt.Fprintf(os.Stderr, "Error fetching entries for %s: %v", ctl.Name, err)
						}*/
						select {
						case <-ctx.Done():
							return
						case <-time.After(30 * time.Second): // Wait with context awareness
						}
						break // Break this loop on error, wait for the next ticker tick.
					}

					if len(entries.Entries) > 0 {
						r.entryTasksChan <- types.EntryTask{
							Entries: entries,
							Index:   start,
						}
						start += int64(len(entries.Entries))
					} else {
						break // No more entries to process, break the loop.
					}
				}
				continue // Continue with the outer loop.
			} else { // Non Google handler
				entries, err := ctl.Client.GetRawEntries(ctx, start, end)
				if err != nil {
					/*if r.options.Verbose {
						fmt.Fprintf(os.Stderr, "Error fetching entries for %s: %v", ctl.Name, err)
					}*/
					select {
					case <-ctx.Done():
						return
					case <-time.After(60 * time.Second): // Wait with context awareness
					}
					continue
				}

				if len(entries.Entries) > 0 {
					r.entryTasksChan <- types.EntryTask{
						Entries: entries,
						Index:   start,
					}
					start += int64(len(entries.Entries))
				}
			}
		}
	}
}
func (r *Runner) fetchAndUpdateSTH(ctx context.Context, ctl types.CtLog, end *int64) error {
	wsth, err := ctl.Client.GetSTH(ctx)
	if err != nil {
		return err
	}
	*end = int64(wsth.TreeSize)
	return nil
}

func (r *Runner) processEntries(results *ct.GetEntriesResponse, start int64) {
	index := start

	for _, entry := range results.Entries {
		index++
		rle, err := ct.RawLogEntryFromLeaf(index, &entry)
		if err != nil {
			/*if r.options.Verbose {
				fmt.Fprintf(os.Stderr, "Failed to get parse entry %d: %v", index, err)
			}*/
			break
		}

		switch entryType := rle.Leaf.TimestampedEntry.EntryType; entryType {
		case ct.X509LogEntryType:
			r.logCertInfo(rle)
		case ct.PrecertLogEntryType:
			r.logPrecertInfo(rle)
		default:
			/*if r.options.Verbose {
				fmt.Fprintln(os.Stderr, "Unknown entry")
			}*/
		}
	}
}

func (r *Runner) logCertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.X509Cert == nil {
		log.Printf("Process cert at index %d: <unparsed: %v>", entry.Index, err)
		return
	}

	if utils.IsSubdomain(parsedEntry.X509Cert.Subject.CommonName, r.rootDomains) {
		//fmt.Println(parsedEntry.X509Cert.Subject.CommonName)
		r.domainsChan <- parsedEntry.X509Cert.Subject.CommonName
	}
	for _, domain := range parsedEntry.X509Cert.DNSNames {
		if utils.IsSubdomain(domain, r.rootDomains) {
			//fmt.Println(domain)
			r.domainsChan <- domain
		}
	}

}

func (r *Runner) logPrecertInfo(entry *ct.RawLogEntry) {
	parsedEntry, err := entry.ToLogEntry()
	if x509.IsFatal(err) || parsedEntry.Precert == nil {
		log.Printf("Process precert at index %d: <unparsed: %v>", entry.Index, err)
		return
	}

	if utils.IsSubdomain(parsedEntry.Precert.TBSCertificate.Subject.CommonName, r.rootDomains) {
		//fmt.Println(parsedEntry.Precert.TBSCertificate.Subject.CommonName)
		r.domainsChan <- parsedEntry.Precert.TBSCertificate.Subject.CommonName
	}
	for _, domain := range parsedEntry.Precert.TBSCertificate.DNSNames {
		if utils.IsSubdomain(domain, r.rootDomains) {
			//fmt.Println(domain)
			r.domainsChan <- domain
		}
	}
}
