package photon

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"

	"github.com/appthreat/vuln-list-update/utils"
	"github.com/cheggaaa/pb"
	"github.com/spf13/afero"
	"golang.org/x/xerrors"
)

const (
	advisoryURL    = "https://packages.broadcom.com/photon/photon_cve_metadata/"
	versionsFile   = "photon_versions.json"
	advisoryFormat = "cve_data_photon%s.json"

	photonDir = "photon"
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
		URL:         advisoryURL,
		AppFs:       afero.NewOsFs(),
		Retry:       retry,
	}
}

func (c Config) getPhotonVersion() ([]string, error) {
	var versions Versions
	res, err := utils.FetchURL(c.URL+versionsFile, "", c.Retry)
	if err != nil {
		return nil, xerrors.Errorf("failed to fetch Photon versions: %w", err)
	}
	if err := json.Unmarshal(res, &versions); err != nil {
		return nil, xerrors.Errorf("failed to decode Photon versions: %w", err)
	}

	return versions.Branches, nil
}

func (c Config) Update() error {
	log.Printf("Fetching Photon")

	versions, err := c.getPhotonVersion()
	if err != nil {
		return xerrors.Errorf("failed to get Photon versions: %w", err)
	}
	for _, version := range versions {
		if strings.ToLower(version) == "dev" {
			continue
		}
		// Release names come from the feed, and the release directory is
		// removed below, so a name must not reach outside the photon tree.
		dirPath, err := utils.SafeJoin(filepath.Join(c.VulnListDir, photonDir), version)
		if err != nil {
			log.Printf("Skip Photon release with an unsafe name: %v", err)
			continue
		}
		res, err := utils.FetchURL(c.URL+fmt.Sprintf(advisoryFormat, version), "", c.Retry)
		if err != nil {
			return xerrors.Errorf("failed to fetch Photon advisory: %w", err)
		}
		var cves []PhotonCVE
		if err := json.Unmarshal(res, &cves); err != nil {
			return xerrors.Errorf("failed to unmarshal Photon advisory: %w", err)
		}
		dir := filepath.Join(photonDir, version)
		log.Printf("Remove Photon %s directory %s", version, dirPath)
		if err := c.AppFs.RemoveAll(dirPath); err != nil {
			return xerrors.Errorf("failed to remove Photon %s directory: %w", version, err)
		}

		bar := pb.StartNew(len(cves))
		for _, def := range cves {
			def.OSVersion = version
			if err = c.saveCVEPerPkg(dir, def.Pkg, def.CveID, def); err != nil {
				return xerrors.Errorf("failed to save CVE-ID per package name: %w", err)
			}
			bar.Increment()
		}
		bar.Finish()
	}

	return nil
}

func (c Config) saveCVEPerPkg(dirName, pkgName, cveID string, cve PhotonCVE) error {
	if cveID == "" {
		log.Printf("CVE-ID is empty")
		return nil
	}

	// Only skip unknown CVE entries (IDs starting with "UNK-" or "Re") that lack version information.
	// Valid CVEs (e.g., "CVE-...") with both ResVer and AffVer as "NA" are still saved,
	// as their status (e.g., "Not Affected") may be meaningful for reporting.
	if (strings.HasPrefix(cveID, "UNK-") || cveID == "Re") &&
		(cve.ResVer == "" || cve.ResVer == "NA") &&
		(cve.AffVer == "" || cve.AffVer == "NA") {
		log.Printf("Skip unknown CVE entry: %s", cveID)
		return nil
	}

	s := strings.Split(cveID, "-")
	if len(s) != 3 {
		log.Printf("invalid CVE-ID: %s", cveID)
		return xerrors.Errorf("invalid CVE-ID format: %s", cveID)
	}

	// The package name and CVE-ID come from the feed and become the
	// directory and file name, so neither may escape the release directory.
	pkgDir, err := utils.SafeJoin(filepath.Join(c.VulnListDir, dirName), pkgName)
	if err == nil {
		err = utils.ValidatePathComponent(cveID)
	}
	if err != nil {
		log.Printf("Skip Photon entry with an unsafe path: %v", err)
		return nil
	}
	fileName := fmt.Sprintf("%s.json", cveID)
	if err := utils.WriteJSON(c.AppFs, pkgDir, fileName, cve); err != nil {
		return xerrors.Errorf("failed to write file: %w", err)
	}
	return nil
}
