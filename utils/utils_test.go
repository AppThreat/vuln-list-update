package utils_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appthreat/vuln-list-update/utils"
)

func TestFetchConcurrently(t *testing.T) {
	const body = "ok"

	tests := []struct {
		name        string
		serverDelay time.Duration
		timeout     time.Duration
		wantErr     bool
	}{
		{
			name:        "timeout fires before workers finish",
			serverDelay: 1 * time.Second,
			timeout:     100 * time.Millisecond,
			wantErr:     true,
		},
		{
			name:    "all urls fetched successfully",
			timeout: 10 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				time.Sleep(tt.serverDelay)
				w.Write([]byte(body))
			}))
			defer srv.Close()

			urls := []string{srv.URL, srv.URL, srv.URL}

			var responses [][]byte
			var err error
			// should not panic even when the timeout fires before workers finish
			require.NotPanics(t, func() {
				responses, err = utils.FetchConcurrently(urls, 2, 0, 0, tt.timeout)
			})

			if tt.wantErr {
				assert.ErrorContains(t, err, "Timeout Fetching URL")
				return
			}

			require.NoError(t, err)
			assert.Len(t, responses, len(urls))
			for _, r := range responses {
				assert.Equal(t, []byte(body), r)
			}
		})
	}
}

func TestFetchURL_Retry(t *testing.T) {
	tests := []struct {
		name      string
		statuses  []int // served in order; the last one repeats
		retry     int
		wantBody  string
		wantErr   int // expected HTTP status in the error, 0 for success
		wantCalls int
	}{
		{
			name:      "permanent 404 fails after one attempt",
			statuses:  []int{http.StatusNotFound},
			retry:     20,
			wantErr:   http.StatusNotFound,
			wantCalls: 1,
		},
		{
			name:      "403 is not retried either",
			statuses:  []int{http.StatusForbidden},
			retry:     3,
			wantErr:   http.StatusForbidden,
			wantCalls: 1,
		},
		{
			name:      "503 then 200 retries and succeeds",
			statuses:  []int{http.StatusServiceUnavailable, http.StatusServiceUnavailable, http.StatusOK},
			retry:     3,
			wantBody:  "ok",
			wantCalls: 3,
		},
		{
			name:      "429 then 200 retries and succeeds",
			statuses:  []int{http.StatusTooManyRequests, http.StatusOK},
			retry:     3,
			wantBody:  "ok",
			wantCalls: 2,
		},
		{
			name:      "408 is retried until the budget runs out",
			statuses:  []int{http.StatusRequestTimeout},
			retry:     2,
			wantErr:   http.StatusRequestTimeout,
			wantCalls: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var waits []int
			utils.SetRetryWait(t, func(i int) time.Duration {
				waits = append(waits, i)
				return 0
			})

			var mu sync.Mutex
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				status := tt.statuses[min(calls, len(tt.statuses)-1)]
				calls++
				mu.Unlock()
				w.WriteHeader(status)
				_, _ = w.Write([]byte("ok"))
			}))
			defer srv.Close()

			body, err := utils.FetchURL(srv.URL, "", tt.retry)
			assert.Equal(t, tt.wantCalls, calls)
			assert.Len(t, waits, tt.wantCalls-1, "one wait before every retry")
			if tt.wantErr != 0 {
				var statusErr *utils.HTTPStatusError
				require.True(t, errors.As(err, &statusErr), "want HTTPStatusError, got %v", err)
				assert.Equal(t, tt.wantErr, statusErr.StatusCode)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantBody, string(body))
		})
	}
}

// Red Hat retries each URL up to 20 times inside a 40 minute window per year;
// the worst case for one URL has to stay well inside it.
func TestMaxRetryWait(t *testing.T) {
	assert.Equal(t, time.Duration(0), utils.MaxRetryWait(0))
	// 1+4+9+16+25 s, then capped at 30 s, plus at most 9 s jitter per retry
	assert.Equal(t, 55*time.Second+9*time.Second*5, utils.MaxRetryWait(5))
	assert.Equal(t, (55+15*30+20*9)*time.Second, utils.MaxRetryWait(20))
	assert.Less(t, utils.MaxRetryWait(20), 15*time.Minute)
}

func TestFetchConcurrently_NotFoundFailsFast(t *testing.T) {
	utils.SetRetryWait(t, func(int) time.Duration { return time.Hour })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	start := time.Now()
	_, err := utils.FetchConcurrently([]string{srv.URL, srv.URL}, 2, 0, 20, time.Minute)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status code: 404")
	assert.Less(t, time.Since(start), 30*time.Second)
}
