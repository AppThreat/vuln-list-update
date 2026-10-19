package oval

type Oval struct {
	Definitions []Definition `xml:"definitions>definition"`
}

type Definition struct {
	Title       string      `xml:"metadata>title"`
	Description string      `xml:"metadata>description"`
	Platform    []string    `xml:"metadata>affected>platform"`
	References  []Reference `xml:"metadata>reference"`
	Criteria    Criteria    `xml:"criteria"`
	Severity    string      `xml:"metadata>advisory>severity"`
	Cves        []Cve       `xml:"metadata>advisory>cve"`
	Issued      Issued      `xml:"metadata>advisory>issued" json:",omitempty"`
	// AffectedCPEList holds the channels the erratum ships to, e.g.
	// "cpe:/o:oracle:linux:9::baseos_latest", "cpe:/a:oracle:linux:6:10:ELS"
	// or "cpe:/a:oracle:exadata_dbserver:23.1.1.0.0::ol8".
	AffectedCPEList []string `xml:"metadata>advisory>affected_cpe_list>cpe" json:",omitempty"`
	// DefinitionID and DefinitionVersion are the OVAL definition's id and
	// version attributes, e.g. "oval:com.oracle.elsa:def:20070057" and "501".
	DefinitionID      string `xml:"id,attr" json:",omitempty"`
	DefinitionVersion string `xml:"version,attr" json:",omitempty"`
}

type Reference struct {
	Source string `xml:"source,attr"`
	URI    string `xml:"ref_url,attr"`
	ID     string `xml:"ref_id,attr"`
}

type Cve struct {
	Impact string `xml:"impact,attr"`
	Href   string `xml:"href,attr"`
	Public string `xml:"public,attr" json:",omitempty"`
	// Oracle encodes cvss2 and cvss3 as "score/vector" (e.g. cvss3="7.3/CVSS:3.1/AV:N/...").
	// Stored verbatim; downstream consumers split into score/vector themselves.
	CVSS2 string `xml:"cvss2,attr" json:",omitempty"`
	CVSS3 string `xml:"cvss3,attr" json:",omitempty"`
	ID    string `xml:",chardata"`
}

type Criteria struct {
	Operator   string      `xml:"operator,attr"`
	Criterias  []*Criteria `xml:"criteria"`
	Criterions []Criterion `xml:"criterion"`
}

type Criterion struct {
	Comment string `xml:"comment,attr"`
}

type Issued struct {
	Date string `xml:"date,attr" json:",omitempty"`
}
