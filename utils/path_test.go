package utils_test

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appthreat/vuln-list-update/utils"
)

func TestSafeJoin(t *testing.T) {
	base := filepath.Join(t.TempDir(), "vuln-list", "bottlerocket")

	tests := []struct {
		name    string
		elems   []string
		want    string
		wantErr bool
	}{
		{
			name:  "plain advisory id",
			elems: []string{"BRSA-1bwujdrkn6nc.json"},
			want:  filepath.Join(base, "BRSA-1bwujdrkn6nc.json"),
		},
		{
			name:  "several components",
			elems: []string{"suse", "2019", "SUSE-SU-2019-1608-1.json"},
			want:  filepath.Join(base, "suse", "2019", "SUSE-SU-2019-1608-1.json"),
		},
		{
			name:  "dots inside a name are fine",
			elems: []string{"..foo..", "1.2.3"},
			want:  filepath.Join(base, "..foo..", "1.2.3"),
		},
		{
			name:    "traversal into another source's tree",
			elems:   []string{"../nvd/2099/CVE-2099-0001.json"},
			wantErr: true,
		},
		{
			name:    "traversal hidden behind a subdirectory",
			elems:   []string{"a/../../x"},
			wantErr: true,
		},
		{
			name:    "parent directory",
			elems:   []string{"..", "x.json"},
			wantErr: true,
		},
		{
			name:    "current directory",
			elems:   []string{"."},
			wantErr: true,
		},
		{
			name:    "absolute path",
			elems:   []string{"/etc/passwd"},
			wantErr: true,
		},
		{
			name:    "windows separator",
			elems:   []string{`..\..\x`},
			wantErr: true,
		},
		{
			name:    "empty component",
			elems:   []string{"suse", "", "x.json"},
			wantErr: true,
		},
		{
			name:    "NUL byte",
			elems:   []string{"x\x00.json"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := utils.SafeJoin(base, tt.elems...)
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, utils.ErrUnsafePath), "want ErrUnsafePath, got %v", err)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
