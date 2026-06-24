package nvd

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/xerrors"

	"github.com/appthreat/vuln-list-update/utils"
)

const (
	retry             = 50
	url20             = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
	apiDir            = "nvd"
	maxResultsPerPage = 2000
	retryAfter        = 30 * time.Second
	apiKeyEnvName     = "NVD_API_KEY"
)

type Option func(*Updater)

func WithLastModEndDate(lastModEndDate time.Time) Option {
	return func(u *Updater) {
		u.lastModEndDate = lastModEndDate
	}
}

func WithMaxResultsPerPage(maxResultsPerPage int) Option {
	return func(u *Updater) {
		u.maxResultsPerPage = maxResultsPerPage
	}
}

func WithBaseURL(url string) Option {
	return func(u *Updater) {
		u.baseURL = url
	}
}

func WithRetry(retry int) Option {
	return func(u *Updater) {
		u.retry = retry
	}
}

func WithRetryAfter(retryAfter time.Duration) Option {
	return func(u *Updater) {
		u.retryAfter = retryAfter
	}
}

type Updater struct {
	baseURL           string
	apiKey            string
	maxResultsPerPage int
	retry             int
	retryAfter        time.Duration
	lastModEndDate    time.Time // time.Now() by default
}

func NewUpdater(opts ...Option) *Updater {
	u := &Updater{
		baseURL:           url20,
		apiKey:            os.Getenv(apiKeyEnvName),
		maxResultsPerPage: maxResultsPerPage,
		retry:             retry,
		retryAfter:        retryAfter,
		lastModEndDate:    time.Now().UTC(),
	}

	for _, opt := range opts {
		opt(u)
	}
	return u
}

func (u Updater) Update() error {
	intervals, err := TimeIntervals(u.lastModEndDate)
	if err != nil {
		return xerrors.Errorf("unable to build time intervals: %w", err)
	}

	for _, interval := range intervals {
		slog.Info("Fetching NVD entries...", slog.String("start", interval.LastModStartDate),
			slog.String("end", interval.LastModEndDate))
		totalResults := 1 // Set a dummy value to start the loop
		for startIndex := 0; startIndex < totalResults; startIndex += u.maxResultsPerPage {
			if totalResults, err = u.saveEntry(interval, startIndex); err != nil {
				return xerrors.Errorf("unable to save entry CVEs for %q: %w", interval, err)
			}
			slog.Info("Fetched NVD entries", slog.Int("total", totalResults), slog.Int("start_index", startIndex))
		}

		// Update last_updated.json after each successfully processed interval
		intervalEnd, err := time.Parse(time.RFC3339, interval.LastModEndDate)
		if err != nil {
			return xerrors.Errorf("unable to parse interval end date %q: %w", interval.LastModEndDate, err)
		}
		if err = utils.SetLastUpdatedDate(apiDir, intervalEnd); err != nil {
			return xerrors.Errorf("unable to update last_updated.json file: %w", err)
		}
	}

	return nil
}

func (u Updater) saveEntry(interval TimeInterval, startIndex int) (int, error) {
	entryURL, err := urlWithParams(u.baseURL, startIndex, u.maxResultsPerPage, interval)
	if err != nil {
		return 0, xerrors.Errorf("unable to get url with query parameters: %w", err)
	}

	entry, err := u.fetchEntry(entryURL)
	if err != nil {
		return 0, xerrors.Errorf("unable to get entry for %q: %w", entryURL, err)
	}
	for _, vuln := range entry.Vulnerabilities {
		if err := utils.SaveCVEPerYear(filepath.Join(utils.VulnListDir(), apiDir), vuln.Cve.ID, vuln.Cve); err != nil {
			return 0, xerrors.Errorf("unable to write %s: %w", vuln.Cve.ID, err)
		}
	}
	return entry.TotalResults, nil
}

func (u Updater) fetchEntry(url string) (Entry, error) {
	var entry Entry
	b, err := u.fetchURL(url)
	if err != nil {
		return Entry{}, xerrors.Errorf("unable to fetch: %w", err)
	}

	if err = json.Unmarshal(b, &entry); err != nil {
		return Entry{}, xerrors.Errorf("unable to decode response for %q: %w", url, err)
	}
	return entry, nil
}

func (u Updater) fetchURL(url string) ([]byte, error) {
	var c http.Client
	for i := 0; i <= u.retry; i++ {
		var retryDelay time.Duration
		if i > 2 {
			retryDelay = 60 * time.Second
		} else {
			retryDelay = time.Duration(15<<uint(i)) * time.Second
			if retryDelay > 60*time.Second {
				retryDelay = 60 * time.Second
			}
		}

		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, xerrors.Errorf("unable to build request for %q: %w", url, err)
		}
		if u.apiKey != "" {
			req.Header.Set("apiKey", u.apiKey)
		}

		resp, err := c.Do(req)
		if err != nil {
			slog.Error("Response error. Try to get the entry again.", slog.String("error", err.Error()))
			if i < u.retry {
				time.Sleep(retryDelay)
			}
			continue
		}

		switch {
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests:
			_ = resp.Body.Close()
			slog.Error("NVD rate limit. Wait to gain access.")
			if i < u.retry {
				ra := u.retryAfter
				// NVD returns the `Retry-After` header as 0.
				// But if they start setting a non-zero value, we can use that duration.
				if headerRetry := resp.Header.Get("Retry-After"); headerRetry != "" && headerRetry != "0" {
					hRetry, err := time.ParseDuration(headerRetry + "s")
					if err == nil {
						ra = hRetry
					}
				}
				time.Sleep(ra)
			}
			continue
		case resp.StatusCode == http.StatusRequestTimeout || (resp.StatusCode >= 500 && resp.StatusCode < 600):
			_ = resp.Body.Close()
			slog.Error("NVD API is unstable. Try to fetch URL again.", slog.String("status_code", resp.Status))
			if i < u.retry {
				time.Sleep(retryDelay)
			}
			continue
		case resp.StatusCode == http.StatusOK:
			body, err := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err != nil {
				slog.Error("Body read error. Try to get the entry again.", slog.String("error", err.Error()))
				if i < u.retry {
					time.Sleep(retryDelay)
				}
				continue
			}
			return body, nil
		default:
			_ = resp.Body.Close()
			return nil, xerrors.Errorf("unexpected status code: %s", resp.Status)
		}
	}
	return nil, xerrors.Errorf("unable to fetch url. Retry limit exceeded.")
}

// TimeIntervals returns time intervals for NVD API
// NVD API doesn't allow to get more than 120 days per request.
// So we need to split the time range into intervals.
func TimeIntervals(endTime time.Time) ([]TimeInterval, error) {
	lastUpdatedDate, err := utils.GetLastUpdatedDate(apiDir)
	if err != nil {
		return nil, xerrors.Errorf("unable to get lastUpdatedDate: %w", err)
	}
	var intervals []TimeInterval
	for endTime.Sub(lastUpdatedDate).Hours()/24 > 120 {
		newLastUpdatedDate := lastUpdatedDate.Add(120 * 24 * time.Hour)
		intervals = append(intervals, TimeInterval{
			LastModStartDate: lastUpdatedDate.UTC().Format(time.RFC3339),
			LastModEndDate:   newLastUpdatedDate.UTC().Format(time.RFC3339),
		})
		lastUpdatedDate = newLastUpdatedDate
	}

	// fill latest interval
	intervals = append(intervals, TimeInterval{
		LastModStartDate: lastUpdatedDate.UTC().Format(time.RFC3339),
		LastModEndDate:   endTime.UTC().Format(time.RFC3339),
	})

	return intervals, nil
}

func urlWithParams(baseUrl string, startIndex, resultsPerPage int, interval TimeInterval) (string, error) {
	u, err := url.Parse(baseUrl)
	if err != nil {
		return "", xerrors.Errorf("unable to parse %q base url: %w", baseUrl, err)
	}
	q := u.Query()
	q.Set("lastModStartDate", interval.LastModStartDate)
	q.Set("lastModEndDate", interval.LastModEndDate)
	q.Set("startIndex", strconv.Itoa(startIndex))
	q.Set("resultsPerPage", strconv.Itoa(resultsPerPage))
	// NVD API doesn't work with escaped `:`
	// So we only need to escape `+` for `Z`:
	// https://nvd.nist.gov/developers/vulnerabilities:
	// `Please note, if a positive Z value is used (such as +01:00 for Central European Time) then the "+" should be encoded in the request as "%2B".`
	decoded, err := url.QueryUnescape(q.Encode())
	if err != nil {
		return "", xerrors.Errorf("unable to decode query params: %w", err)
	}
	u.RawQuery = decoded
	return u.String(), nil
}
