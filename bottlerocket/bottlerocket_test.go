package bottlerocket_test

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appthreat/vuln-list-update/bottlerocket"
)

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name      string
		gzipFile  string
		wantFiles []string
		wantErr   string
	}{
		{
			name:     "happy path",
			gzipFile: "testdata/updateinfo.xml.gz",
			wantFiles: []string{
				"BRSA-1bwujdrkn6nc.json",
				"BRSA-kdg8bd1th2gb.json",
			},
		},
		{
			name:     "invalid gzip",
			gzipFile: "testdata/updateinfo_invalid.xml.gz",
			wantErr:  "failed to decompress updateinfo",
		},
		{
			name:     "invalid xml",
			gzipFile: "testdata/invalid_xml.gz",
			wantErr:  "failed to decode updateinfo XML",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				buf, err := os.ReadFile(tc.gzipFile)
				require.NoError(t, err)
				_, _ = w.Write(buf)
			}))
			defer ts.Close()

			tmpDir := t.TempDir()
			c := bottlerocket.NewConfig(
				bottlerocket.WithURL(fmt.Sprintf("%s/updateinfo.xml.gz", ts.URL)),
				bottlerocket.WithVulnListDir(tmpDir),
			)

			err := c.Update()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)

			entries, err := os.ReadDir(filepath.Join(tmpDir, "bottlerocket"))
			require.NoError(t, err)
			assert.Len(t, entries, len(tc.wantFiles))

			for _, wantFile := range tc.wantFiles {
				got, err := os.ReadFile(filepath.Join(tmpDir, "bottlerocket", wantFile))
				require.NoError(t, err, "failed to open the result file")

				want, err := os.ReadFile(filepath.Join("testdata", "golden", wantFile))
				require.NoError(t, err, "failed to open the golden file")

				assert.JSONEq(t, string(want), string(got))
			}
		})
	}
}

// gzipUpdateInfo builds an updateinfo.xml.gz body holding one update per ID.
func gzipUpdateInfo(t *testing.T, ids ...string) []byte {
	t.Helper()
	var xmlBody bytes.Buffer
	xmlBody.WriteString(`<?xml version="1.0"?>` + "\n<updates>\n")
	for _, id := range ids {
		fmt.Fprintf(&xmlBody, "<update><id>%s</id><title>kernel CVE-2099-0001</title></update>\n", id)
	}
	xmlBody.WriteString("</updates>\n")

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	_, err := gw.Write(xmlBody.Bytes())
	require.NoError(t, err)
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

// listFiles returns every regular file under root, relative to root.
func listFiles(t *testing.T, root string) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		files = append(files, rel)
		return err
	})
	require.NoError(t, err)
	return files
}

// Advisory IDs come from the feed and become file names. IDs that would
// write into another source's tree, or outside the vuln-list directory
// altogether, must be skipped without failing the whole update.
func TestConfig_Update_UnsafeIDs(t *testing.T) {
	body := gzipUpdateInfo(t,
		"BRSA-good",
		"../nvd/2099/CVE-2099-0001",
		"a/../../x",
		"../../outside",
		"/abs/escape",
		`..\..\win`,
		"..",
		"",
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer ts.Close()

	root := t.TempDir()
	vulnListDir := filepath.Join(root, "vuln-list")
	c := bottlerocket.NewConfig(
		bottlerocket.WithURL(ts.URL+"/updateinfo.xml.gz"),
		bottlerocket.WithVulnListDir(vulnListDir),
	)
	require.NoError(t, c.Update())

	assert.Equal(t, []string{filepath.Join("vuln-list", "bottlerocket", "BRSA-good.json")}, listFiles(t, root))
}
