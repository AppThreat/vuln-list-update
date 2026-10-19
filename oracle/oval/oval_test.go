package oval_test

import (
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appthreat/vuln-list-update/oracle/oval"
)

var update = flag.Bool("update", false, "update golden files")

func TestConfig_Update(t *testing.T) {
	testCases := []struct {
		name             string
		appFs            afero.Fs
		bzip2FileNames   map[string]string
		goldenFiles      map[string]string
		expectedErrorMsg string
	}{
		{
			name:  "positive test",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/all-positive-data.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/oracle/2007/ELSA-2007-0057.json": "testdata/golden/ELSA-2007-0057.json",
				"/tmp/oval/oracle/2008/ELSA-2008-0110.json": "testdata/golden/ELSA-2008-0110.json",
				"/tmp/oval/oracle/2009/ELSA-2009-1203.json": "testdata/golden/ELSA-2009-1203.json",
				"/tmp/oval/oracle/2010/ELSA-2010-0809.json": "testdata/golden/ELSA-2010-0809.json",
				"/tmp/oval/oracle/2011/ELSA-2011-1268.json": "testdata/golden/ELSA-2011-1268.json",
				"/tmp/oval/oracle/2012/ELSA-2012-1261.json": "testdata/golden/ELSA-2012-1261.json",
				"/tmp/oval/oracle/2013/ELSA-2013-1732.json": "testdata/golden/ELSA-2013-1732.json",
				"/tmp/oval/oracle/2014/ELSA-2014-2010.json": "testdata/golden/ELSA-2014-2010.json",
				"/tmp/oval/oracle/2015/ELSA-2015-2561.json": "testdata/golden/ELSA-2015-2561.json",
				"/tmp/oval/oracle/2016/ELSA-2016-3646.json": "testdata/golden/ELSA-2016-3646.json",
				"/tmp/oval/oracle/2017/ELSA-2017-3516.json": "testdata/golden/ELSA-2017-3516.json",
				"/tmp/oval/oracle/2018/ELSA-2018-3410.json": "testdata/golden/ELSA-2018-3410.json",
				"/tmp/oval/oracle/2019/ELSA-2019-4820.json": "testdata/golden/ELSA-2019-4820.json",
				"/tmp/oval/oracle/2019/ELSA-2019-4821.json": "testdata/golden/ELSA-2019-4821.json",
			},
		},
		{
			name:  "positive test file format ELSA-XXXX-XXXX-X",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/elsa-2018-1196-1.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/oracle/2018/ELSA-2018-1196-1.json": "testdata/golden/ELSA-2018-1196-1.json",
			},
			expectedErrorMsg: "",
		},
		{
			// Real multi-release erratum: the affected CPE list (ELS and
			// Exadata channels) and the definition id/version are kept.
			name:  "affected CPE list and definition attributes",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/elsa-with-cpes.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/oracle/2023/ELSA-2023-12143.json": "testdata/golden/ELSA-2023-12143.json",
			},
		},
		{
			// Titles come from the feed and the ELSA ID parsed out of them
			// becomes the year directory and file name. IDs that would
			// write outside oval/oracle are skipped without failing.
			name:  "unsafe ELSA IDs",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/unsafe-elsa-ids.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/oracle/2099/ELSA-2099-0001.json": "testdata/golden/ELSA-2099-0001.json",
			},
		},
		{
			name:  "invalid filesystem write read only path",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/all-positive-data.xml.bz2",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to remove Oracle Linux OVAL directory: operation not permitted",
		},
		{
			name:  "invalid title format",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/invalid-title-format.xml.bz2",
			},
			goldenFiles: map[string]string{
				"/tmp/oval/oracle/2007/ELSA-2007-0057.json": "testdata/golden/ELSA-2007-0057.json",
			},
		},
		{
			name:             "404",
			appFs:            afero.NewMemMapFs(),
			bzip2FileNames:   map[string]string{},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to fetch Oracle Linux OVAL: failed to fetch URL: HTTP error. status code: 404, url:",
		},
		{
			name:  "invalid file format",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/invalid.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decode Oracle Linux OVAL XML: bzip2 data invalid: bad magic value",
		},
		{
			name:  "empty file format",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/EOF.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decode Oracle Linux OVAL XML: unexpected EOF",
		},
		{
			name:  "broken XML",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/oval/com.oracle.elsa-all.xml.bz2": "testdata/broken-oval-data.xml.bz2",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to decode Oracle Linux OVAL XML: XML syntax error on line 536: element <criteria> closed by </affected>",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				filePath, ok := tc.bzip2FileNames[r.URL.Path]
				if !ok {
					http.NotFound(w, r)
					return
				}
				b, err := os.ReadFile(filePath)
				assert.NoError(t, err, tc.name)
				_, err = w.Write(b)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()
			url := ts.URL + "/oval/com.oracle.elsa-all.xml.bz2"
			c := oval.Config{
				VulnListDir: "/tmp",
				URL:         url,
				AppFs:       tc.appFs,
				Retry:       0,
			}
			err := c.Update()
			switch {
			case tc.expectedErrorMsg != "":
				assert.Contains(t, err.Error(), tc.expectedErrorMsg, tc.name)
				return
			default:
				assert.NoError(t, err, tc.name)
			}

			fileCount := 0
			err = afero.Walk(c.AppFs, "/", func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return err
				}
				if info.IsDir() {
					return nil
				}
				fileCount += 1

				actual, err := afero.ReadFile(c.AppFs, path)
				assert.NoError(t, err, tc.name)

				goldenPath, ok := tc.goldenFiles[path]
				assert.True(t, ok, tc.name)

				if *update {
					err = os.WriteFile(goldenPath, actual, 0666)
					assert.NoError(t, err, tc.name)
				}

				expected, err := os.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				assert.Equal(t, expected, actual, tc.name)

				return nil
			})
			assert.Equal(t, len(tc.goldenFiles), fileCount, tc.name)
			assert.NoError(t, err, tc.name)
		})
	}

}

// Advisories Oracle withdraws must disappear from vuln-list on the next run,
// but only once a complete feed has been downloaded and decoded; a failed
// or empty fetch must leave the existing tree alone.
func TestConfig_Update_RemovesWithdrawnAdvisories(t *testing.T) {
	const (
		withdrawn   = "/tmp/oval/oracle/2007/ELSA-2007-9999.json"
		otherSource = "/tmp/oval/redhat/2007/RHSA-2007-0057.json"
	)
	testCases := []struct {
		name          string
		feed          string // empty: the server answers 404
		wantErr       string
		wantWithdrawn bool
	}{
		{
			name: "complete feed replaces the tree",
			feed: "testdata/elsa-2018-1196-1.xml.bz2",
		},
		{
			name:          "failed download keeps the tree",
			wantErr:       "failed to fetch Oracle Linux OVAL",
			wantWithdrawn: true,
		},
		{
			name:          "broken XML keeps the tree",
			feed:          "testdata/broken-oval-data.xml.bz2",
			wantErr:       "failed to decode Oracle Linux OVAL XML",
			wantWithdrawn: true,
		},
		{
			name:          "feed without definitions keeps the tree",
			feed:          "testdata/no-definitions.xml.bz2",
			wantErr:       "Oracle Linux OVAL has no definitions",
			wantWithdrawn: true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.feed == "" {
					http.NotFound(w, r)
					return
				}
				b, err := os.ReadFile(tc.feed)
				require.NoError(t, err)
				_, _ = w.Write(b)
			}))
			defer ts.Close()

			appFs := afero.NewMemMapFs()
			require.NoError(t, afero.WriteFile(appFs, withdrawn, []byte("{}"), 0600))
			require.NoError(t, afero.WriteFile(appFs, otherSource, []byte("{}"), 0600))

			c := oval.Config{
				VulnListDir: "/tmp",
				URL:         ts.URL + "/oval/com.oracle.elsa-all.xml.bz2",
				AppFs:       appFs,
				Retry:       0,
			}
			err := c.Update()
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
				ok, err := afero.Exists(appFs, "/tmp/oval/oracle/2018/ELSA-2018-1196-1.json")
				require.NoError(t, err)
				assert.True(t, ok, "advisory from the feed is written")
			}

			ok, err := afero.Exists(appFs, withdrawn)
			require.NoError(t, err)
			assert.Equal(t, tc.wantWithdrawn, ok, "withdrawn advisory present")

			ok, err = afero.Exists(appFs, otherSource)
			require.NoError(t, err)
			assert.True(t, ok, "other trees are never touched")
		})
	}
}
