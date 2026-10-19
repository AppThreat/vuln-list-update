package cvrf_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appthreat/vuln-list-update/suse/cvrf"
)

var update = flag.Bool("update", false, "update golden files")

// createArchive creates a tar.gz archive from the given directory.
// gzip is used instead of bzip2 because Go's compress/bzip2 package
// only provides a Reader. The production code detects the format by
// URL suffix and handles both .tar.bz2 and .tar.gz.
func createArchive(t *testing.T, dir string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	require.NoError(t, tw.AddFS(os.DirFS(dir)))
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())

	return buf.Bytes()
}

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name        string
		appFs       afero.Fs
		archiveDir  string
		goldenFiles map[string]string
		wantErr     string
	}{
		{
			name:       "positive test sles",
			appFs:      afero.NewMemMapFs(),
			archiveDir: "testdata/cvrf",
			goldenFiles: map[string]string{
				"/tmp/cvrf/suse/suse/2018/SUSE-SU-2018-1784-1.json":         "testdata/golden/SUSE-SU-2018-1784-1.json",
				"/tmp/cvrf/suse/suse/2019/SUSE-SU-2019-14018-1.json":        "testdata/golden/SUSE-SU-2019-14018-1.json",
				"/tmp/cvrf/suse/suse/2019/SUSE-SU-2019-1608-1.json":         "testdata/golden/SUSE-SU-2019-1608-1.json",
				"/tmp/cvrf/suse/suse/2019/SUSE-SU-2019-3294-1.json":         "testdata/golden/SUSE-SU-2019-3294-1.json",
				"/tmp/cvrf/suse/suse/2019/SUSE-SU-2019-3295-1.json":         "testdata/golden/SUSE-SU-2019-3295-1.json",
				"/tmp/cvrf/suse/opensuse/2015/openSUSE-SU-2015-0225-1.json": "testdata/golden/openSUSE-SU-2015-0225-1.json",
				"/tmp/cvrf/suse/opensuse/2015/openSUSE-SU-2015-0798-1.json": "testdata/golden/openSUSE-SU-2015-0798-1.json",
				"/tmp/cvrf/suse/opensuse/2015/openSUSE-SU-2015-1289-1.json": "testdata/golden/openSUSE-SU-2015-1289-1.json",
				"/tmp/cvrf/suse/opensuse/2016/openSUSE-SU-2016-3233-1.json": "testdata/golden/openSUSE-SU-2016-3233-1.json",
				"/tmp/cvrf/suse/opensuse/2018/openSUSE-SU-2018-1633-1.json": "testdata/golden/openSUSE-SU-2018-1633-1.json",
				"/tmp/cvrf/suse/opensuse/2016/openSUSE-SU-2016-0874-1.json": "testdata/golden/openSUSE-SU-2016-0874-1.json",
			},
		},
		{
			name:        "broken XML",
			appFs:       afero.NewMemMapFs(),
			archiveDir:  "testdata/broken-cvrf",
			goldenFiles: map[string]string{},
			wantErr:     "failed to decode SUSE XML",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			archiveData := createArchive(t, tc.archiveDir)

			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, err := w.Write(archiveData)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()

			c := cvrf.Config{
				VulnListDir: "/tmp",
				URL:         ts.URL + "/cvrf.tar.gz",
				AppFs:       tc.appFs,
			}
			err := c.Update()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr, tc.name)
				return
			}
			require.NoError(t, err, tc.name)

			fileCount := 0
			err = afero.Walk(c.AppFs, "/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount++

				actual, err := afero.ReadFile(c.AppFs, path)
				require.NoError(t, err, tc.name)

				goldenPath, ok := tc.goldenFiles[path]
				assert.True(t, ok, tc.name)
				if *update {
					err = os.WriteFile(goldenPath, actual, 0666)
					assert.NoError(t, err, tc.name)
				}
				expected, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				assert.Equal(t, string(expected), string(actual), tc.name)

				return nil
			})
			assert.NoError(t, err, tc.name)
			assert.Equal(t, len(tc.goldenFiles), fileCount, tc.name)
		})
	}
}

// createArchiveFromEntries creates a tar.gz archive holding the given
// file name to content pairs, in order.
func createArchiveFromEntries(t *testing.T, entries [][2]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	for _, e := range entries {
		require.NoError(t, tw.WriteHeader(&tar.Header{
			Name:     e[0],
			Mode:     0600,
			Size:     int64(len(e[1])),
			Typeflag: tar.TypeReg,
		}))
		_, err := tw.Write([]byte(e[1]))
		require.NoError(t, err)
	}
	require.NoError(t, tw.Close())
	require.NoError(t, gw.Close())
	return buf.Bytes()
}

func cvrfDoc(id string) string {
	return fmt.Sprintf("<cvrfdoc><DocumentTitle>test</DocumentTitle><DocumentTracking>"+
		"<Identification><ID>%s</ID></Identification></DocumentTracking></cvrfdoc>", id)
}

// walkFiles returns every regular file in fs, sorted.
func walkFiles(t *testing.T, fs afero.Fs) []string {
	t.Helper()
	var files []string
	err := afero.Walk(fs, "/", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		files = append(files, path)
		return nil
	})
	require.NoError(t, err)
	sort.Strings(files)
	return files
}

// The OS name comes from archive entry names and the year and file name from
// each document's tracking ID. A crafted archive must not be able to write
// outside the cvrf/suse tree, and bad entries are skipped, not fatal.
func TestConfig_Update_UnsafePaths(t *testing.T) {
	archive := createArchiveFromEntries(t, [][2]string{
		{"cvrf-suse-su-2099-0001-1.xml", cvrfDoc("SUSE-SU-2099:0001-1")},
		// year escapes via the tracking ID
		{"cvrf-suse-su-2099-0002-1.xml", cvrfDoc("SUSE-SU-2099/../../../../../../../escaped:pwn-1")},
		// file name escapes via the tracking ID
		{"cvrf-suse-su-2099-0003-1.xml", cvrfDoc("SUSE-SU-2099:0003/../../../../nvd/x-1")},
		// OS name escapes via the archive entry name
		{"cvrf-..-su-2099-0004-1.xml", cvrfDoc("SUSE-SU-2099:0004-1")},
		{"cvrf-.-su-2099-0005-1.xml", cvrfDoc("SUSE-SU-2099:0005-1")},
		// absolute path in the tracking ID
		{"cvrf-suse-su-2099-0006-1.xml", cvrfDoc("SUSE-SU-/escaped:0006-1")},
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(archive)
	}))
	defer ts.Close()

	c := cvrf.Config{
		VulnListDir: "/tmp/vuln-list",
		URL:         ts.URL + "/cvrf.tar.gz",
		AppFs:       afero.NewMemMapFs(),
	}
	require.NoError(t, c.Update())

	assert.Equal(t, []string{"/tmp/vuln-list/cvrf/suse/suse/2099/SUSE-SU-2099-0001-1.json"}, walkFiles(t, c.AppFs))
}
