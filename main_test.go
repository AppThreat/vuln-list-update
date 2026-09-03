package main

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
