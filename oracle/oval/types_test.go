package oval_test

import (
	"encoding/xml"
	"os"
	"testing"

	"github.com/kylelemons/godebug/pretty"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appthreat/vuln-list-update/oracle/oval"
)

func TestRedhatCVEJSON_UnmarshalJSON(t *testing.T) {
	tests := map[string]struct {
		in   string
		want *oval.Oval
	}{
		"nested_criterias_elsa_data": {
			// https://linux.oracle.com/oval/com.oracle.elsa-20070057.xml
			in: "testdata/ELSA-2007-0057.xml",
			want: &oval.Oval{
				Definitions: []oval.Definition{
					{
						Title:       "\nELSA-2007-0057:  Moderate: bind security update  (MODERATE)\n",
						Description: "\n [30:9.3.3-8]\n - added fix for #224445 - CVE-2007-0493 BIND might crash after\n   attempting to read free()-ed memory\n - added fix for #225229 - CVE-2007-0494 BIND dnssec denial of service\n - Resolves: rhbz#224445\n - Resolves: rhbz#225229 \n",
						Platform:    []string{"Oracle Linux 5"},
						References: []oval.Reference{
							{
								Source: "elsa",
								URI:    "http://linux.oracle.com/errata/ELSA-2007-0057.html",
								ID:     "ELSA-2007-0057",
							},
							{
								Source: "CVE",
								URI:    "http://linux.oracle.com/cve/CVE-2007-0493.html",
								ID:     "CVE-2007-0493",
							},
							{
								Source: "CVE",
								URI:    "http://linux.oracle.com/cve/CVE-2007-0494.html",
								ID:     "CVE-2007-0494",
							},
						},
						Criteria: oval.Criteria{
							Operator: "AND",
							Criterias: []*oval.Criteria{
								{
									Operator: "OR",
									Criterias: []*oval.Criteria{
										{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oval.Criterion{
												{
													Comment: "bind-devel is earlier than 30:9.3.3-8.el5",
												},
												{
													Comment: "bind-devel is signed with the Oracle Linux 5 key",
												},
											},
										},
										{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oval.Criterion{
												{
													Comment: "bind-sdb is earlier than 30:9.3.3-8.el5",
												},
												{
													Comment: "bind-sdb is signed with the Oracle Linux 5 key",
												},
											},
										},
										{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oval.Criterion{
												{
													Comment: "bind-libs is earlier than 30:9.3.3-8.el5",
												},
												{
													Comment: "bind-libs is signed with the Oracle Linux 5 key",
												},
											},
										},
										{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oval.Criterion{
												{
													Comment: "bind-libbind-devel is earlier than 30:9.3.3-8.el5",
												},
												{
													Comment: "bind-libbind-devel is signed with the Oracle Linux 5 key",
												},
											},
										},
										{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oval.Criterion{
												{
													Comment: "bind-utils is earlier than 30:9.3.3-8.el5",
												},
												{
													Comment: "bind-utils is signed with the Oracle Linux 5 key",
												},
											},
										},
										{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oval.Criterion{
												{
													Comment: "bind-chroot is earlier than 30:9.3.3-8.el5",
												},
												{
													Comment: "bind-chroot is signed with the Oracle Linux 5 key",
												},
											},
										},
										{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oval.Criterion{
												{
													Comment: "bind is earlier than 30:9.3.3-8.el5",
												},
												{
													Comment: "bind is signed with the Oracle Linux 5 key",
												},
											},
										},
										{
											Operator:  "AND",
											Criterias: nil,
											Criterions: []oval.Criterion{
												{
													Comment: "caching-nameserver is earlier than 30:9.3.3-8.el5",
												},
												{
													Comment: "caching-nameserver is signed with the Oracle Linux 5 key",
												},
											},
										},
									},
									Criterions: nil,
								},
							},
							Criterions: []oval.Criterion{
								{
									Comment: "Oracle Linux 5 is installed",
								},
							},
						},
						Severity: "MODERATE",
						Cves: []oval.Cve{
							{
								Impact: "",
								Href:   "http://linux.oracle.com/cve/CVE-2007-0493.html",
								ID:     "CVE-2007-0493",
							},
							{
								Impact: "",
								Href:   "http://linux.oracle.com/cve/CVE-2007-0494.html",
								ID:     "CVE-2007-0494",
							},
						},
						Issued: oval.Issued{
							Date: "2007-06-26",
						},
						DefinitionID:      "oval:com.oracle.elsa:def:20070057",
						DefinitionVersion: "501",
					},
				},
			},
		},
	}
	for testname, tt := range tests {
		t.Run(testname, func(t *testing.T) {
			xmlByte, err := os.ReadFile(tt.in)
			if err != nil {
				require.NoError(t, err)
			}

			got := &oval.Oval{}
			err = xml.Unmarshal(xmlByte, got)
			if err != nil {
				require.NoError(t, err)
			}
			if !assert.Equal(t, got, tt.want) {
				t.Errorf("[%s]\n diff: %s", testname, pretty.Compare(got, tt.want))
			}
		})
	}
}

// The affected CPE list carries the channels an erratum ships to (ELS,
// Exadata, UEK, ...), which Platform alone doesn't tell apart.
func TestDefinition_AffectedCPEList(t *testing.T) {
	// trimmed from https://linux.oracle.com/security/oval/com.oracle.elsa-all.xml.bz2
	xmlByte, err := os.ReadFile("testdata/elsa-with-cpes.xml")
	require.NoError(t, err)

	got := &oval.Oval{}
	require.NoError(t, xml.Unmarshal(xmlByte, got))
	require.Len(t, got.Definitions, 1)

	def := got.Definitions[0]
	assert.Equal(t, "oval:com.oracle.elsa:def:202312143", def.DefinitionID)
	assert.Equal(t, "501", def.DefinitionVersion)
	assert.Equal(t, []string{"Oracle Linux 6", "Oracle Linux 8"}, def.Platform)
	assert.Equal(t, []string{
		"cpe:/a:oracle:exadata_dbserver:21.2.24.0.0::ovs3",
		"cpe:/a:oracle:linux:6:10:ELS",
		"cpe:/a:oracle:exadata_dbserver:23.1.1.0.0::ol8",
		"cpe:/a:oracle:exadata_dbserver:21.2.23.0.0::ovs3",
	}, def.AffectedCPEList)
}
