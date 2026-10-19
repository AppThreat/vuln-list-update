package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appthreat/vuln-list-update/utils"
)

func TestRunWithRetry(t *testing.T) {
	tests := []struct {
		name       string
		maxRetries int
		failures   int
		wantErr    string
		wantCalls  int
	}{
		{
			name:       "success on first attempt",
			maxRetries: 3,
			wantCalls:  1,
		},
		{
			name:       "success after transient failures",
			maxRetries: 3,
			failures:   2,
			wantCalls:  3,
		},
		{
			name:       "success on last retry",
			maxRetries: 3,
			failures:   3,
			wantCalls:  4,
		},
		{
			name:       "all retries exhausted",
			maxRetries: 3,
			failures:   10,
			wantErr:    "update failed after 4 attempts",
			wantCalls:  4,
		},
		{
			name:       "no retries",
			maxRetries: 0,
			failures:   1,
			wantErr:    "update failed after 1 attempts",
			wantCalls:  1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			update := func() error {
				calls++
				if calls <= tt.failures {
					return errors.New("transient error")
				}
				return nil
			}

			err := runWithRetry(tt.maxRetries, time.Millisecond, update)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Contains(t, err.Error(), "transient error")
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tt.wantCalls, calls)
		})
	}
}

// nvd keeps its own last_updated entry and leaves it unchanged after an empty
// API response; main must not overwrite it, while other targets still get
// stamped with the run time.
func TestRecordLastUpdated(t *testing.T) {
	oldDir := utils.VulnListDir()
	t.Cleanup(func() { utils.SetVulnListDir(oldDir) })
	dir := t.TempDir()
	utils.SetVulnListDir(dir)

	before := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "last_updated.json"),
		[]byte(`{"alpine": "2026-10-01T00:00:00Z", "nvd": "2026-10-01T00:00:00Z"}`), 0600))

	require.NoError(t, recordLastUpdated("nvd", now))
	require.NoError(t, recordLastUpdated("alpine", now))

	got, err := utils.GetLastUpdatedDate("nvd")
	require.NoError(t, err)
	assert.True(t, before.Equal(got), "nvd entry unchanged, got %s", got)

	got, err = utils.GetLastUpdatedDate("alpine")
	require.NoError(t, err)
	assert.True(t, now.Equal(got), "alpine entry stamped, got %s", got)
}
