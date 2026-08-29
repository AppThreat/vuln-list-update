package git_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/appthreat/vuln-list-update/git"
)

// setupOrigin creates a local bare repository that plays the role of the
// GitHub remote, with a single initial commit on main.
func setupOrigin(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	seed := filepath.Join(dir, "seed")
	require.NoError(t, os.MkdirAll(seed, 0700))
	runGit(t, seed, "init", "-b", "main")
	require.NoError(t, os.WriteFile(filepath.Join(seed, "README.md"), []byte("test"), 0600))
	runGit(t, seed, "add", ".")
	runGit(t, seed, "commit", "--message", "initial commit")

	origin := filepath.Join(dir, "origin.git")
	runGit(t, dir, "clone", "--bare", seed, origin)
	return origin
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "git %v failed: %s", args, out)
	return string(out)
}

// commitAndPush mimics main.go: commit the updated files, then push.
func commitAndPush(t *testing.T, repoPath, message string) {
	t.Helper()
	gc := git.Config{}
	require.NoError(t, gc.Commit(repoPath, "./", message))
	require.NoError(t, gc.Push(repoPath, "main"))
}

// rivalUpdate simulates another workflow committing and pushing to the
// remote branch while this run is still in progress.
func rivalUpdate(t *testing.T, origin, dir, path, content string) {
	t.Helper()
	runGit(t, filepath.Dir(origin), "clone", "--quiet", origin, dir)
	require.NoError(t, os.MkdirAll(filepath.Dir(filepath.Join(dir, path)), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(dir, path), []byte(content), 0600))
	runGit(t, dir, "add", ".")
	runGit(t, dir, "commit", "--message", "rival update")
	runGit(t, dir, "push", "origin", "main")
}

func assertRemoteFile(t *testing.T, origin, path string) {
	t.Helper()
	work := filepath.Dir(origin)
	verify := filepath.Join(work, "verify-"+filepath.Base(path))
	runGit(t, work, "clone", "--quiet", origin, verify)
	_, err := os.Stat(filepath.Join(verify, path))
	assert.NoError(t, err, path)
}

// The remote branch advances when another workflow pushes while this run
// is still updating data. Push must rebase the local commit onto the
// remote changes instead of failing with a non-fast-forward rejection.
func TestPush_RemoteAdvanced(t *testing.T) {
	t.Setenv("GIT_AUTHOR_NAME", "test")
	t.Setenv("GIT_AUTHOR_EMAIL", "test@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "test")
	t.Setenv("GIT_COMMITTER_EMAIL", "test@example.com")

	origin := setupOrigin(t)
	work := filepath.Dir(origin)

	local := filepath.Join(work, "local")
	runGit(t, work, "clone", "--quiet", origin, local)

	rivalUpdate(t, origin, filepath.Join(work, "rival"), "alpine/CVE-2026-0001.json", "{}")

	// This run commits on top of its now stale clone and must still push.
	require.NoError(t, os.MkdirAll(filepath.Join(local, "nvd"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(local, "nvd", "CVE-2026-0002.json"), []byte("{}"), 0600))
	commitAndPush(t, local, "NVD")

	assertRemoteFile(t, origin, "alpine/CVE-2026-0001.json")
	assertRemoteFile(t, origin, "nvd/CVE-2026-0002.json")
}

// Both workflows may touch last_updated.json in the same window; the
// rebase must resolve the conflict in favor of the newer local data.
func TestPush_ConflictPrefersLocalData(t *testing.T) {
	t.Setenv("GIT_AUTHOR_NAME", "test")
	t.Setenv("GIT_AUTHOR_EMAIL", "test@example.com")
	t.Setenv("GIT_COMMITTER_NAME", "test")
	t.Setenv("GIT_COMMITTER_EMAIL", "test@example.com")

	origin := setupOrigin(t)
	work := filepath.Dir(origin)

	rivalJSON := "{\n  \"updated\": \"2026-08-29T23:00:00Z\"\n}"
	rivalUpdate(t, origin, filepath.Join(work, "rival"), "last_updated.json", rivalJSON)

	localJSON := "{\n  \"updated\": \"2026-08-29T23:30:00Z\"\n}"
	local := filepath.Join(work, "local")
	runGit(t, work, "clone", "--quiet", origin, local)
	require.NoError(t, os.WriteFile(filepath.Join(local, "last_updated.json"), []byte(localJSON), 0600))
	commitAndPush(t, local, "NVD")

	verify := filepath.Join(work, "verify")
	runGit(t, work, "clone", "--quiet", origin, verify)
	b, err := os.ReadFile(filepath.Join(verify, "last_updated.json"))
	require.NoError(t, err)
	assert.Contains(t, string(b), "2026-08-29T23:30:00Z")
}
