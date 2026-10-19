package cvrf

import (
	"archive/tar"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/appthreat/vuln-list-update/utils"
)

const (
	cvrfArchiveURL = "http://ftp.suse.com/pub/projects/security/cvrf.tar.bz2"
	cvrfDir        = "cvrf"
	suseDir        = "suse"
	retries        = 5
)

var fileRegexp = regexp.MustCompile(`^cvrf-(.*?)-`)

type Config struct {
	VulnListDir string
	URL         string
	AppFs       afero.Fs
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URL:         cvrfArchiveURL,
		AppFs:       afero.NewOsFs(),
	}
}

func (c Config) Update() error {
	log.Print("Fetching SUSE CVRF archive...")

	// The SUSE server is sometimes unstable, so download the whole archive into
	// memory before processing. Streaming directly from the HTTP response would
	// make it hard to distinguish a mid-transfer disconnection (which surfaces
	// as a truncated tar) from a legitimate parse error. The archive is only a
	// few hundred MB, which fits comfortably in memory on CI runners.
	body, err := utils.FetchURL(c.URL, "", retries)
	if err != nil {
		return xerrors.Errorf("failed to download CVRF archive: %w", err)
	}

	var decompressed io.Reader
	switch {
	case strings.HasSuffix(c.URL, ".tar.bz2"):
		// The upstream archive is .tar.bz2, which is the only format used in production.
		decompressed = bzip2.NewReader(bytes.NewReader(body))
	case strings.HasSuffix(c.URL, ".tar.gz"):
		// Go's compress/bzip2 lacks a Writer, so tests use .tar.gz instead.
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return xerrors.Errorf("failed to decompress gzip: %w", err)
		}
		defer gr.Close()
		decompressed = gr
	default:
		return xerrors.Errorf("unsupported archive format: %s", c.URL)
	}
	tr := tar.NewReader(decompressed)

	for {
		hdr, err := tr.Next()
		switch {
		case errors.Is(err, io.EOF):
			return nil
		case err != nil:
			return xerrors.Errorf("failed to read tar entry: %w", err)
		case hdr.Typeflag != tar.TypeReg:
			continue
		}

		filename := filepath.Base(hdr.Name)
		// archive contains non-XML files (e.g. LICENSE), so skip them
		if !strings.HasSuffix(filename, ".xml") {
			continue
		}
		match := fileRegexp.FindStringSubmatch(filename)
		if match == nil {
			continue
		}
		osName := match[1]

		data, err := io.ReadAll(tr)
		if err != nil {
			return xerrors.Errorf("failed to read tar entry data: %w", err)
		}

		if len(data) == 0 {
			log.Printf("empty CVRF xml: %s", filename)
			continue
		}

		if !utf8.Valid(data) {
			log.Printf("invalid UTF-8: %s", filename)
			data = []byte(strings.ToValidUTF8(string(data), ""))
		}

		var cv Cvrf
		if err = xml.Unmarshal(data, &cv); err != nil {
			return xerrors.Errorf("failed to decode SUSE XML (%s): %w", filename, err)
		}

		if err = c.saveCvrfPerYear(osName, cv.Tracking.ID, cv); err != nil {
			return xerrors.Errorf("failed to save CVRF: %w", err)
		}
	}
}

func (c Config) saveCvrfPerYear(osName string, cvrfID string, data Cvrf) error {
	s := strings.Split(cvrfID, "-")
	if len(s) < 4 {
		log.Printf("invalid CVRF-ID format: %s", cvrfID)
		return nil
	}

	year := strings.Split(s[2], ":")[0]
	if len(year) < 4 {
		log.Printf("invalid CVRF-ID format: %s", cvrfID)
		return nil
	}

	// The OS name comes from the archive entry name and the year and file
	// name from the document's tracking ID, so none of them may step outside
	// the cvrf/suse tree.
	advisoryID := strings.Replace(cvrfID, ":", "-", 1)
	yearDir, err := utils.SafeJoin(filepath.Join(c.VulnListDir, cvrfDir, suseDir), osName, year)
	if err == nil {
		err = utils.ValidatePathComponent(advisoryID)
	}
	if err != nil {
		log.Printf("skip CVRF with an unsafe path: %v", err)
		return nil
	}

	fileName := fmt.Sprintf("%s.json", advisoryID)
	if err := utils.WriteJSON(c.AppFs, yearDir, fileName, data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
