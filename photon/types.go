package photon

type Versions struct {
	Branches []string `json:"branches"`
}

type PhotonCVE struct {
	OSVersion string  `json:"os_version"`
	CveID     string  `json:"cve_id"`
	Pkg       string  `json:"pkg"`
	CveScore  float64 `json:"cve_score"`
	AffVer    string  `json:"aff_ver"`
	ResVer    string  `json:"res_ver"`
	// Status is the feed's verdict for the package, e.g. "Fixed" or
	// "Not Affected"; it is what distinguishes an unaffected NA/NA row.
	Status string `json:"status,omitempty"`
}
