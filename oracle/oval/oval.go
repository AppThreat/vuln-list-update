package oval

import (
	"bytes"
	"compress/bzip2"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"

	"github.com/appthreat/vuln-list-update/utils"
)

var (
	ErrInvalidELSAID = xerrors.New("invalid ELSA ID")
)

const (
	ovalDir   = "oval"
	oracleDir = "oracle"
	ovalURL   = "https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2"
	retry     = 5
)

type Config struct {
	VulnListDir string
	URL         string
	AppFs       afero.Fs
	Retry       int
}

func NewConfig() Config {
	return Config{
		VulnListDir: utils.VulnListDir(),
		URL:         ovalURL,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) Update() error {
	log.Printf("Fetching Oracle")

	res, err := utils.FetchURL(c.URL, "", c.Retry)
	if err != nil {
		return xerrors.Errorf("failed to fetch Oracle Linux OVAL: %w", err)
	}

	var ov Oval
	ovalReader := bzip2.NewReader(bytes.NewReader(res))
	err = xml.NewDecoder(ovalReader).Decode(&ov)
	if err != nil {
		return xerrors.Errorf("failed to decode Oracle Linux OVAL XML: %w", err)
	}

	dir := filepath.Join(ovalDir, oracleDir)
	bar := pb.StartNew(len(ov.Definitions))
	for _, def := range ov.Definitions {
		def.Title = strings.TrimSpace(def.Title)
		def.Description = strings.TrimSpace(def.Description)

		//def.Title example: "\nELSA-2019-4827:  docker-engine docker-cli security update (IMPORTANT)"
		elsaID := strings.TrimSpace(strings.Split(def.Title, ":")[0])
		if err = c.saveELSAPerYear(dir, elsaID, def); err != nil {
			if err == ErrInvalidELSAID {
				log.Printf("Invalid ELSA ID: %s\n", elsaID)
				continue
			}
			if errors.Is(err, utils.ErrUnsafePath) {
				log.Printf("Skip ELSA with an unsafe ID: %v", err)
				continue
			}

			return xerrors.Errorf("failed to save ELSAPerYear: %w", err)
		}
		bar.Increment()
	}
	bar.Finish()

	return nil
}

func (c Config) saveELSAPerYear(dirName string, elsaID string, data interface{}) error {
	s := strings.Split(elsaID, "-")
	if len(s) < 3 {
		return ErrInvalidELSAID
	}

	// The ID is parsed out of the feed's title and becomes both the year
	// directory and the file name, so neither may escape the oracle tree.
	if err := utils.ValidatePathComponent(elsaID); err != nil {
		return err
	}
	yearDir, err := utils.SafeJoin(filepath.Join(c.VulnListDir, dirName), s[1])
	if err != nil {
		return err
	}
	if err := utils.WriteJSON(c.AppFs, yearDir, fmt.Sprintf("%s.json", elsaID), data); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
