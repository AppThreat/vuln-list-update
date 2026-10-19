package nvd_test

import (
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appthreat/vuln-list-update/nvd"
)

// A real NVD API 2.0 record (CVE-2024-7450, trimmed to the v4.0 metrics)
// must survive a decode/encode round trip through Entry without losing or
// renaming any cvssData property.
func TestCvssMetricV40_RoundTrip(t *testing.T) {
	b, err := os.ReadFile("testdata/fixtures/cvssV40.json")
	require.NoError(t, err)

	var raw struct {
		Vulnerabilities []struct {
			Cve struct {
				Metrics struct {
					CvssMetricV40 []map[string]any `json:"cvssMetricV40"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	require.NoError(t, json.Unmarshal(b, &raw))
	require.Len(t, raw.Vulnerabilities, 1)
	want := raw.Vulnerabilities[0].Cve.Metrics.CvssMetricV40
	require.Len(t, want, 2)
	for _, m := range want {
		require.Len(t, m["cvssData"], 36, "fixture should carry every property NVD sends")
	}

	var entry nvd.Entry
	require.NoError(t, json.Unmarshal(b, &entry))
	require.Len(t, entry.Vulnerabilities, 1)

	got, err := json.Marshal(entry.Vulnerabilities[0].Cve.Metrics.CvssMetricV40)
	require.NoError(t, err)
	wantJSON, err := json.Marshal(want)
	require.NoError(t, err)
	assert.JSONEq(t, string(wantJSON), string(got))
}

// Every property of https://csrc.nist.gov/schema/nvd/api/2.0/external/cvss-v4.0.json
// (its "properties" plus the score/severity pairs declared under "allOf")
// must map to exactly one CvssDataV40 field, with the same spelling and case.
func TestCvssDataV40_SchemaProperties(t *testing.T) {
	schemaProperties := []string{
		"version", "vectorString",
		"attackVector", "attackComplexity", "attackRequirements", "privilegesRequired", "userInteraction",
		"vulnConfidentialityImpact", "vulnIntegrityImpact", "vulnAvailabilityImpact",
		"subConfidentialityImpact", "subIntegrityImpact", "subAvailabilityImpact",
		"exploitMaturity",
		"confidentialityRequirement", "integrityRequirement", "availabilityRequirement",
		"modifiedAttackVector", "modifiedAttackComplexity", "modifiedAttackRequirements",
		"modifiedPrivilegesRequired", "modifiedUserInteraction",
		"modifiedVulnConfidentialityImpact", "modifiedVulnIntegrityImpact", "modifiedVulnAvailabilityImpact",
		"modifiedSubConfidentialityImpact", "modifiedSubIntegrityImpact", "modifiedSubAvailabilityImpact",
		"Safety", "Automatable", "Recovery",
		"valueDensity", "vulnerabilityResponseEffort", "providerUrgency",
		// allOf
		"baseScore", "baseSeverity",
		"threatScore", "threatSeverity",
		"environmentalScore", "environmentalSeverity",
	}

	var tags []string
	typ := reflect.TypeOf(nvd.CvssDataV40{})
	for i := 0; i < typ.NumField(); i++ {
		tag := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		tags = append(tags, tag)
	}
	assert.ElementsMatch(t, schemaProperties, tags)
}
