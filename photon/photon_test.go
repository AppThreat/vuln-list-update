package photon_test

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appthreat/vuln-list-update/photon"
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
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/cve_data_photon1.0.json",
				"/photon_cve_metadata/cve_data_photon2.0.json": "testdata/cve_data_photon2.0.json",
				"/photon_cve_metadata/cve_data_photon3.0.json": "testdata/cve_data_photon3.0.json",
			},
			goldenFiles: map[string]string{
				"/tmp/photon/1.0/zlib/CVE-2016-9843.json":           "testdata/golden/CVE-2016-9843.json",
				"/tmp/photon/1.0/zookeeper/CVE-2017-5637.json":      "testdata/golden/CVE-2017-5637.json",
				"/tmp/photon/1.0/apache-tomcat/CVE-2017-12617.json": "testdata/golden/CVE-2017-12617.json",
				"/tmp/photon/1.0/binutils/CVE-2018-10372.json":      "testdata/golden/CVE-2018-10372.json",
				"/tmp/photon/1.0/binutils/CVE-2019-12972.json":      "testdata/golden/CVE-2019-12972.json",
				"/tmp/photon/2.0/jq/CVE-2015-8863.json":             "testdata/golden/CVE-2015-8863.json",
				"/tmp/photon/2.0/bash/CVE-2016-9401.json":           "testdata/golden/CVE-2016-9401.json",
				"/tmp/photon/2.0/ansible/CVE-2017-7473.json":        "testdata/golden/CVE-2017-7473.json",
				"/tmp/photon/2.0/ansible/CVE-2018-16876.json":       "testdata/golden/CVE-2018-16876.json",
				"/tmp/photon/2.0/ansible/CVE-2019-10156.json":       "testdata/golden/CVE-2019-10156.json",
				"/tmp/photon/3.0/ansible/CVE-2019-3828.json":        "testdata/golden/CVE-2019-3828.json",
				"/tmp/photon/3.0/apache-tomcat/CVE-2019-0199.json":  "testdata/golden/CVE-2019-0199.json",
				"/tmp/photon/3.0/apache-tomcat/CVE-2019-10072.json": "testdata/golden/CVE-2019-10072.json",
				"/tmp/photon/3.0/binutils/CVE-2017-16826.json":      "testdata/golden/CVE-2017-16826.json",
			},
		},
		{
			name:  "invalid photon_versions.json",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json": "testdata/invalid_photon_versions.json",
			},
			expectedErrorMsg: "failed to decode Photon versions",
		},
		{
			name:  "invalid filesystem write read only path",
			appFs: afero.NewReadOnlyFs(afero.NewOsFs()),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/cve_data_photon1.0.json",
				"/photon_cve_metadata/cve_data_photon2.0.json": "testdata/cve_data_photon2.0.json",
				"/photon_cve_metadata/cve_data_photon3.0.json": "testdata/cve_data_photon3.0.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to remove Photon 1.0 directory: operation not permitted",
		},
		{
			name:             "404",
			appFs:            afero.NewMemMapFs(),
			bzip2FileNames:   map[string]string{},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to fetch Photon versions",
		},
		{
			name:  "EOF file",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/invalid.txt",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to unmarshal Photon advisory: unexpected end of JSON input",
		},
		{
			name:  "invalid json format",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/cve_data_photon_invalid_format.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "failed to unmarshal Photon advisory: invalid character ']' after object key:value pair",
		},
		{
			name:  "invalid CVE-ID",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/cve_data_photon3.0_invalid_cveid.json",
			},
			goldenFiles:      map[string]string{},
			expectedErrorMsg: "invalid CVE-ID format",
		},
		{
			name:  "empty CVE-ID",
			appFs: afero.NewMemMapFs(),
			bzip2FileNames: map[string]string{
				"/photon_cve_metadata/photon_versions.json":    "testdata/photon_versions.json",
				"/photon_cve_metadata/cve_data_photon1.0.json": "testdata/cve_data_photon1.0.json",
				"/photon_cve_metadata/cve_data_photon2.0.json": "testdata/cve_data_photon_empty_cveid.json",
				"/photon_cve_metadata/cve_data_photon3.0.json": "testdata/cve_data_photon3.0.json",
			},
			goldenFiles: map[string]string{
				"/tmp/photon/1.0/zlib/CVE-2016-9843.json":           "testdata/golden/CVE-2016-9843.json",
				"/tmp/photon/1.0/zookeeper/CVE-2017-5637.json":      "testdata/golden/CVE-2017-5637.json",
				"/tmp/photon/1.0/apache-tomcat/CVE-2017-12617.json": "testdata/golden/CVE-2017-12617.json",
				"/tmp/photon/1.0/binutils/CVE-2018-10372.json":      "testdata/golden/CVE-2018-10372.json",
				"/tmp/photon/1.0/binutils/CVE-2019-12972.json":      "testdata/golden/CVE-2019-12972.json",
				"/tmp/photon/3.0/ansible/CVE-2019-3828.json":        "testdata/golden/CVE-2019-3828.json",
				"/tmp/photon/3.0/apache-tomcat/CVE-2019-0199.json":  "testdata/golden/CVE-2019-0199.json",
				"/tmp/photon/3.0/apache-tomcat/CVE-2019-10072.json": "testdata/golden/CVE-2019-10072.json",
				"/tmp/photon/3.0/binutils/CVE-2017-16826.json":      "testdata/golden/CVE-2017-16826.json",
			},
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
				b, err := ioutil.ReadFile(filePath)
				assert.NoError(t, err, tc.name)
				_, err = w.Write(b)
				assert.NoError(t, err, tc.name)
			}))
			defer ts.Close()
			url := ts.URL + "/photon_cve_metadata/"
			c := photon.Config{
				VulnListDir: "/tmp",
				URL:         url,
				AppFs:       tc.appFs,
				Retry:       0,
			}
			err := c.Update()
			switch {
			case tc.expectedErrorMsg != "":
				require.NotNil(t, err, tc.name)
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
				if !ok {
					fmt.Println(path)
				}
				assert.True(t, ok, tc.name)

				if *update {
					err = ioutil.WriteFile(goldenPath, actual, 0666)
					assert.NoError(t, err, tc.name)
				}

				expected, err := ioutil.ReadFile(goldenPath)
				assert.NoError(t, err, tc.name)

				assert.Equal(t, expected, actual, tc.name)

				return nil
			})
			assert.Equal(t, len(tc.goldenFiles), fileCount, tc.name)
			assert.NoError(t, err, tc.name)
		})
	}
}

// Release names, package names and CVE-IDs all come from the feed and become
// paths; the release directory is even removed before it is rewritten. Unsafe
// values must be skipped without touching anything outside the photon tree.
func TestConfig_Update_UnsafePaths(t *testing.T) {
	versions := `{"branches": ["1.0", "..", "../nvd", "x/../../y", ""]}`
	advisories := `[
  {"cve_id": "CVE-2099-0001", "pkg": "zlib", "cve_score": 7.5, "aff_ver": "all versions before 1.2.8-5.ph1 are vulnerable", "res_ver": "1.2.8-5.ph1"},
  {"cve_id": "CVE-2099-0002", "pkg": "../../nvd/2099", "cve_score": 7.5, "aff_ver": "NA", "res_ver": "1.0-1.ph1"},
  {"cve_id": "CVE-2099-0003", "pkg": "..", "cve_score": 7.5, "aff_ver": "NA", "res_ver": "1.0-1.ph1"},
  {"cve_id": "CVE-2099/../../../x-0004", "pkg": "zlib", "cve_score": 7.5, "aff_ver": "NA", "res_ver": "1.0-1.ph1"}
]`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/photon_cve_metadata/photon_versions.json":
			_, _ = w.Write([]byte(versions))
		case r.URL.Path == "/photon_cve_metadata/cve_data_photon1.0.json":
			_, _ = w.Write([]byte(advisories))
		default:
			// any other release resolves to an empty, valid advisory list
			_, _ = w.Write([]byte("[]"))
		}
	}))
	defer ts.Close()

	appFs := afero.NewMemMapFs()
	otherSource := "/tmp/nvd/2099/CVE-2099-9999.json"
	require.NoError(t, afero.WriteFile(appFs, otherSource, []byte("{}"), 0600))

	c := photon.Config{
		VulnListDir: "/tmp",
		URL:         ts.URL + "/photon_cve_metadata/",
		AppFs:       appFs,
		Retry:       0,
	}
	require.NoError(t, c.Update())

	assert.ElementsMatch(t, []string{otherSource, "/tmp/photon/1.0/zlib/CVE-2099-0001.json"}, listFiles(t, appFs))
}

// listFiles returns every regular file in fs.
func listFiles(t *testing.T, fs afero.Fs) []string {
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
	return files
}

// serveFeed serves photon_versions.json and one advisory file per release.
func serveFeed(t *testing.T, versions string, advisories map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/photon_cve_metadata/photon_versions.json" {
			_, _ = w.Write([]byte(versions))
			return
		}
		for version, file := range advisories {
			if r.URL.Path == "/photon_cve_metadata/cve_data_photon"+version+".json" {
				b, err := os.ReadFile(file)
				require.NoError(t, err)
				_, _ = w.Write(b)
				return
			}
		}
		http.NotFound(w, r)
	}))
}

// "UNK-*" and "Re" placeholders must be skipped even when they carry real
// version bounds; they used to fall through to the CVE-ID format check and
// abort the whole update.
func TestConfig_Update_UnknownIDs(t *testing.T) {
	ts := serveFeed(t, `{"branches": ["3.0"]}`, map[string]string{
		"3.0": "testdata/cve_data_photon_unknown_ids.json",
	})
	defer ts.Close()

	c := photon.Config{
		VulnListDir: "/tmp",
		URL:         ts.URL + "/photon_cve_metadata/",
		AppFs:       afero.NewMemMapFs(),
		Retry:       0,
	}
	require.NoError(t, c.Update())

	assert.Equal(t, []string{"/tmp/photon/3.0/ansible/CVE-2019-3828.json"}, listFiles(t, c.AppFs))
}

// The feed's status tells "Not Affected" NA/NA rows apart from affected
// ones; without it consumers treat res_ver "NA" as affected at every version.
func TestConfig_Update_Status(t *testing.T) {
	ts := serveFeed(t, `{"branches": ["5.0"]}`, map[string]string{
		"5.0": "testdata/cve_data_photon_status.json",
	})
	defer ts.Close()

	c := photon.Config{
		VulnListDir: "/tmp",
		URL:         ts.URL + "/photon_cve_metadata/",
		AppFs:       afero.NewMemMapFs(),
		Retry:       0,
	}
	require.NoError(t, c.Update())

	want := map[string]string{
		"/tmp/photon/5.0/curl/CVE-2024-11053.json": `{"os_version": "5.0", "cve_id": "CVE-2024-11053", "pkg": "curl", "cve_score": 3.4,
			"aff_ver": "all versions before 8.12.0-1.ph5 are vulnerable", "res_ver": "8.12.0-1.ph5", "status": "Fixed"}`,
		"/tmp/photon/5.0/curl/CVE-2024-0853.json": `{"os_version": "5.0", "cve_id": "CVE-2024-0853", "pkg": "curl", "cve_score": 5.3,
			"aff_ver": "NA", "res_ver": "NA", "status": "Not Affected"}`,
	}
	assert.ElementsMatch(t, []string{"/tmp/photon/5.0/curl/CVE-2024-11053.json", "/tmp/photon/5.0/curl/CVE-2024-0853.json"}, listFiles(t, c.AppFs))
	for path, wantJSON := range want {
		got, err := afero.ReadFile(c.AppFs, path)
		require.NoError(t, err)
		assert.JSONEq(t, wantJSON, string(got), path)
	}
}
