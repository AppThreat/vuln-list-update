package utils

import (
	"testing"
	"time"
)

// SetRetryWait replaces FetchURL's wait between attempts for the duration of the test.
func SetRetryWait(t *testing.T, f func(retry int) time.Duration) {
	t.Helper()
	old := retryWait
	retryWait = f
	t.Cleanup(func() { retryWait = old })
}
