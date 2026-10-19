package securitydataapi

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/appthreat/vuln-list-update/utils"
)

// A URL that keeps failing must give up long before the per-year timeout,
// otherwise one bad URL throws away the whole year (and the run-level retry
// then repeats that for every attempt).
func TestRetryBudgetFitsFetchTimeout(t *testing.T) {
	assert.Less(t, utils.MaxRetryWait(retry), fetchTimeout/3,
		"worst-case retry wait for one URL (%s) must stay well below fetchTimeout (%s)",
		utils.MaxRetryWait(retry), fetchTimeout)
}
