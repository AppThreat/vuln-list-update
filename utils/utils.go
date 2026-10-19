package utils

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/parnurzeal/gorequest"
	"golang.org/x/xerrors"
	pb "gopkg.in/cheggaaa/pb.v1"
)

var vulnListDir = filepath.Join(CacheDir(), "vuln-list")

func CacheDir() string {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		cacheDir = os.TempDir()
	}
	dir := filepath.Join(cacheDir, "vuln-list-update")
	return dir
}

func SetVulnListDir(dir string) {
	vulnListDir = dir
}

func VulnListDir() string {
	return vulnListDir
}

func SaveCVEPerYear(dirPath string, cveID string, data interface{}) error {
	s := strings.Split(cveID, "-")
	if len(s) != 3 {
		return xerrors.Errorf("invalid CVE-ID format: %s\n", cveID)
	}

	yearDir := filepath.Join(dirPath, s[1])
	if err := os.MkdirAll(yearDir, os.ModePerm); err != nil {
		return err
	}

	filePath := filepath.Join(yearDir, fmt.Sprintf("%s.json", cveID))
	if err := Write(filePath, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}

func Write(filePath string, data interface{}) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, os.ModePerm); err != nil {
		return xerrors.Errorf("failed to create %s: %w", dir, err)
	}

	f, err := os.Create(filePath)
	if err != nil {
		return xerrors.Errorf("file create error: %w", err)
	}
	defer f.Close()

	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return xerrors.Errorf("JSON marshal error: %w", err)
	}

	_, err = f.Write(b)
	if err != nil {
		return xerrors.Errorf("file write error: %w", err)
	}
	return nil
}

// GenWorkers generate workers
func GenWorkers(num, wait int, wg *sync.WaitGroup) chan<- func() {
	tasks := make(chan func())
	for i := 0; i < num; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range tasks {
				f()
				time.Sleep(time.Duration(wait) * time.Second)
			}
		}()
	}
	return tasks
}

// DeleteNil deletes nil in errs
func DeleteNil(errs []error) (new []error) {
	for _, err := range errs {
		if err != nil {
			new = append(new, err)
		}
	}
	return new
}

// TrimSpaceNewline deletes space character and newline character(CR/LF)
func TrimSpaceNewline(str string) string {
	str = strings.TrimSpace(str)
	return strings.Trim(str, "\r\n")
}

const (
	// maxRetryBackoff caps the quadratic part of FetchURL's wait between
	// attempts. Without it the waits grow without bound: 20 retries used to
	// add up to about 49 minutes for a single URL.
	maxRetryBackoff = 30 * time.Second
	// maxRetryJitter is the exclusive upper bound, in seconds, of the random
	// jitter added to every wait.
	maxRetryJitter = 10
)

// HTTPStatusError is returned when a server answers with a status other than 200.
type HTTPStatusError struct {
	URL        string
	StatusCode int
}

func (e *HTTPStatusError) Error() string {
	return fmt.Sprintf("HTTP error. status code: %d, url: %s", e.StatusCode, e.URL)
}

// retryBackoff is the deterministic part of the wait before retry i (1-based).
func retryBackoff(i int) time.Duration {
	return min(time.Duration(i*i)*time.Second, maxRetryBackoff)
}

// retryWait returns how long FetchURL sleeps before retry i (1-based).
// It is a variable so tests can avoid real sleeps.
var retryWait = func(i int) time.Duration {
	return retryBackoff(i) + time.Duration(RandInt()%maxRetryJitter)*time.Second
}

// MaxRetryWait returns the longest FetchURL can spend waiting between
// attempts for the given number of retries, i.e. its worst-case retry budget
// for one URL on top of the requests themselves.
func MaxRetryWait(retry int) time.Duration {
	var total time.Duration
	for i := 1; i <= retry; i++ {
		total += retryBackoff(i) + (maxRetryJitter-1)*time.Second
	}
	return total
}

// isRetryable reports whether a failed fetch may succeed if tried again.
// Client errors are permanent (a missing advisory stays missing), except
// 408 Request Timeout, 425 Too Early and 429 Too Many Requests.
func isRetryable(err error) bool {
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		return true
	}
	switch statusErr.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return true
	}
	return statusErr.StatusCode < 400 || statusErr.StatusCode >= 500
}

// FetchURL returns HTTP response body with retry. Permanent client errors
// (see isRetryable) are returned after the first attempt.
func FetchURL(url, apikey string, retry int) (res []byte, err error) {
	for i := 0; i <= retry; i++ {
		if i > 0 {
			wait := retryWait(i)
			log.Printf("retry after %s\n", wait)
			time.Sleep(wait)
		}
		res, err = fetchURL(url, map[string]string{"api-key": apikey})
		if err == nil {
			return res, nil
		}
		if !isRetryable(err) {
			break
		}
	}
	return nil, xerrors.Errorf("failed to fetch URL: %w", err)
}

func RandInt() int {
	seed, _ := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	return int(seed.Int64())
}

func fetchURL(url string, headers map[string]string) ([]byte, error) {
	req := gorequest.New().Get(url)
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	resp, body, errs := req.Type("text").EndBytes()
	if len(errs) > 0 {
		return nil, xerrors.Errorf("HTTP error. url: %s, err: %w", url, errs[0])
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPStatusError{URL: url, StatusCode: resp.StatusCode}
	}
	return body, nil
}

// FetchConcurrently fetches concurrently
func FetchConcurrently(urls []string, concurrency, wait, retry int, timeout time.Duration) (responses [][]byte, err error) {
	// Each URL pushes at most one value into each channel, so buffering to
	// len(urls) means writers never block. They are intentionally not closed:
	// receivers read a bounded number of values (no range), and closing while
	// workers are still sending would panic. GC reclaims them once unreferenced.
	reqChan := make(chan string, len(urls))
	resChan := make(chan []byte, len(urls))
	errChan := make(chan error, len(urls))

	go func() {
		for _, url := range urls {
			reqChan <- url
		}
	}()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	bar := pb.StartNew(len(urls))
	var wg sync.WaitGroup
	tasks := GenWorkers(concurrency, wait, &wg)
	for range urls {
		fn := func() {
			url := <-reqChan
			res, err := FetchURL(url, "", retry)
			if err != nil {
				errChan <- err
				return
			}
			resChan <- res
		}
		select {
		case tasks <- fn:
		case <-timer.C:
			close(tasks)
			return nil, xerrors.New("Timeout Fetching URL")
		}
		bar.Increment()
	}
	bar.Finish()
	close(tasks)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-timer.C:
		return nil, xerrors.New("Timeout Fetching URL")
	}

	var errs []error
	for range urls {
		select {
		case res := <-resChan:
			responses = append(responses, res)
		case err := <-errChan:
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return responses, errors.Join(errs...)
	}
	return responses, nil
}

// Major returns major version
func Major(osVer string) (majorVersion string) {
	return strings.Split(osVer, ".")[0]
}

func IsCommandAvailable(name string) bool {
	cmd := exec.Command(name, "--help")
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

func Exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func Exec(command string, args []string) (string, error) {
	cmd := exec.Command(command, args...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		log.Println(stderrBuf.String())
		return "", xerrors.Errorf("failed to exec: %w", err)
	}
	return stdoutBuf.String(), nil
}

func LookupEnv(key, defaultValue string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultValue
}
