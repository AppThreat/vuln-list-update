package git

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/appthreat/vuln-list-update/utils"
	"golang.org/x/xerrors"
)

const maxPushAttempts = 3

type Operations interface {
	CloneOrPull(string, string, string) (map[string]struct{}, error)
	RemoteBranch(string) ([]string, error)
	Checkout(string, string) error
}

type Config struct {
}

func (gc Config) CloneOrPull(url, repoPath, branch string, debug bool) (map[string]struct{}, error) {
	exists, err := utils.Exists(filepath.Join(repoPath, ".git"))
	if err != nil {
		return nil, err
	}

	updatedFiles := map[string]struct{}{}
	if exists {
		if debug {
			log.Println("Skip git pull")
			return nil, nil
		}

		log.Println("git pull")
		files, err := pull(url, repoPath, branch)
		if err != nil {
			return nil, xerrors.Errorf("git pull error: %w", err)
		}

		for _, filename := range files {
			updatedFiles[strings.TrimSpace(filename)] = struct{}{}
		}
	} else {
		if err = os.MkdirAll(repoPath, 0700); err != nil {
			return nil, err
		}
		if err := clone(url, repoPath, branch); err != nil {
			return nil, err
		}

		if err := fetchAll(repoPath); err != nil {
			return nil, err
		}
		err = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
			if info.IsDir() {
				return nil
			}
			updatedFiles[path] = struct{}{}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	return updatedFiles, nil
}

func clone(url, repoPath, branch string) error {
	commandAndArgs := []string{"clone", "--depth", "1", url, repoPath}
	if branch != "" {
		commandAndArgs = append(commandAndArgs, "-b", branch)
	}
	cmd := exec.Command("git", commandAndArgs...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return xerrors.Errorf("failed to clone: %w", err)
	}
	return nil
}

func pull(url, repoPath, branch string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)

	remoteCmd := []string{"remote", "get-url", "--push", "origin"}
	output, err := utils.Exec("git", append(commandArgs, remoteCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git rev-list: %w", err)
	}
	remoteURL := strings.TrimSpace(output)
	if remoteURL != url {
		return nil, xerrors.Errorf("remote url is %s, target is %s", remoteURL, url)
	}

	revParseCmd := []string{"rev-list", "-n", "1", "--all"}
	output, err = utils.Exec("git", append(commandArgs, revParseCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git rev-list: %w", err)
	}
	commitHash := strings.TrimSpace(output)
	if len(commitHash) == 0 {
		log.Println("no commit yet")
		return nil, nil
	}

	pullCmd := []string{"pull", "origin"}
	if branch != "" {
		pullCmd = append(pullCmd, branch)
	}
	if _, err = utils.Exec("git", append(commandArgs, pullCmd...)); err != nil {
		return nil, xerrors.Errorf("error in git pull: %w", err)
	}

	fetchCmd := []string{"fetch", "--prune"}
	if _, err = utils.Exec("git", append(commandArgs, fetchCmd...)); err != nil {
		return nil, xerrors.Errorf("error in git fetch: %w", err)
	}

	diffCmd := []string{"diff", commitHash, "HEAD", "--name-only"}
	output, err = utils.Exec("git", append(commandArgs, diffCmd...))
	if err != nil {
		return nil, err
	}
	updatedFiles := strings.Split(strings.TrimSpace(output), "\n")
	return updatedFiles, nil
}

func fetchAll(repoPath string) error {
	commandArgs := generateGitArgs(repoPath)
	configCmd := []string{"config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"}
	if _, err := utils.Exec("git", append(commandArgs, configCmd...)); err != nil {
		return xerrors.Errorf("error in git config: %w", err)
	}

	fetchCmd := []string{"fetch", "--all"}
	if _, err := utils.Exec("git", append(commandArgs, fetchCmd...)); err != nil {
		return xerrors.Errorf("error in git fetch: %w", err)
	}
	return nil
}

func (gc Config) Commit(repoPath, targetPath, message string) error {
	commandArgs := generateGitArgs(repoPath)
	addCmd := []string{"add", filepath.Join(repoPath, targetPath)}
	if _, err := utils.Exec("git", append(commandArgs, addCmd...)); err != nil {
		return xerrors.Errorf("error in git add: %w", err)
	}

	commitCmd := []string{"commit", "--message", message}
	if _, err := utils.Exec("git", append(commandArgs, commitCmd...)); err != nil {
		return xerrors.Errorf("error in git commit: %w", err)
	}

	return nil
}

func (gc Config) Push(repoPath, branch string) error {
	commandArgs := generateGitArgs(repoPath)

	// Other workflows push to the same branch while this run is still
	// updating data, so the local commit has to be rebased on top of the
	// remote changes or the push is rejected as non-fast-forward.
	var lastErr error
	for attempt := 1; attempt <= maxPushAttempts; attempt++ {
		fetchCmd := []string{"fetch", "origin", branch}
		if _, err := utils.Exec("git", append(commandArgs, fetchCmd...)); err != nil {
			return xerrors.Errorf("error in git fetch: %w", err)
		}

		// Every job stamps its own key in last_updated.json, so the rebase
		// below can resolve a conflict there with this run's whole copy and
		// roll back keys other jobs pushed meanwhile. Read both sides first
		// so the file can be merged per key afterwards.
		local, err := lastUpdatedAt(commandArgs, "HEAD")
		if err != nil {
			return err
		}
		remote, err := lastUpdatedAt(commandArgs, fmt.Sprintf("origin/%s", branch))
		if err != nil {
			return err
		}

		// During a rebase "theirs" is the commit being replayed, so this
		// resolves conflicts in favor of the newer local data.
		rebaseCmd := []string{"rebase", "-X", "theirs", fmt.Sprintf("origin/%s", branch)}
		if _, err := utils.Exec("git", append(commandArgs, rebaseCmd...)); err != nil {
			abortCmd := []string{"rebase", "--abort"}
			_, _ = utils.Exec("git", append(commandArgs, abortCmd...))
			return xerrors.Errorf("error in git rebase: %w", err)
		}

		if err := mergeLastUpdated(repoPath, branch, local, remote); err != nil {
			return err
		}

		pushCmd := []string{"push", "origin", branch}
		if _, err := utils.Exec("git", append(commandArgs, pushCmd...)); err != nil {
			lastErr = err
			log.Printf("git push attempt %d/%d failed, retrying", attempt, maxPushAttempts)
			time.Sleep(time.Duration(attempt) * 2 * time.Second)
			continue
		}
		return nil
	}
	return xerrors.Errorf("error in git push: %w", lastErr)
}

// lastUpdatedAt returns last_updated.json as committed at rev, or an empty
// map when rev doesn't have the file.
func lastUpdatedAt(commandArgs []string, rev string) (utils.LastUpdated, error) {
	lsTreeCmd := []string{"ls-tree", "--name-only", rev, "--", utils.LastUpdatedFile}
	output, err := utils.Exec("git", append(commandArgs, lsTreeCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git ls-tree: %w", err)
	}
	lastUpdated := utils.LastUpdated{}
	if strings.TrimSpace(output) == "" {
		return lastUpdated, nil
	}

	showCmd := []string{"show", fmt.Sprintf("%s:%s", rev, utils.LastUpdatedFile)}
	output, err = utils.Exec("git", append(commandArgs, showCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git show: %w", err)
	}
	if err = json.Unmarshal([]byte(output), &lastUpdated); err != nil {
		return nil, xerrors.Errorf("invalid %s at %s: %w", utils.LastUpdatedFile, rev, err)
	}
	return lastUpdated, nil
}

// mergeLastUpdated runs after the rebase. It sets every key of
// last_updated.json to the newer of this run's and the remote's timestamps
// and, if the rebased file differs from that, amends this run's commit.
func mergeLastUpdated(repoPath, branch string, local, remote utils.LastUpdated) error {
	merged := utils.LastUpdated{}
	for key, t := range remote {
		merged[key] = t
	}
	for key, t := range local {
		if cur, ok := merged[key]; !ok || t.After(cur) {
			merged[key] = t
		}
	}
	if len(merged) == 0 {
		return nil
	}

	commandArgs := generateGitArgs(repoPath)
	rebased, err := lastUpdatedAt(commandArgs, "HEAD")
	if err != nil {
		return err
	}
	if sameLastUpdated(rebased, merged) {
		return nil
	}

	// Only ever amend this run's own commit, never one already on the remote.
	countCmd := []string{"rev-list", "--count", fmt.Sprintf("origin/%s..HEAD", branch)}
	output, err := utils.Exec("git", append(commandArgs, countCmd...))
	if err != nil {
		return xerrors.Errorf("error in git rev-list: %w", err)
	}
	if strings.TrimSpace(output) == "0" {
		return nil
	}

	log.Printf("Merging %s per key after the rebase", utils.LastUpdatedFile)
	b, err := json.MarshalIndent(merged, "", "  ")
	if err != nil {
		return xerrors.Errorf("failed to marshal %s: %w", utils.LastUpdatedFile, err)
	}
	if err = os.WriteFile(filepath.Join(repoPath, utils.LastUpdatedFile), b, 0600); err != nil {
		return xerrors.Errorf("failed to write %s: %w", utils.LastUpdatedFile, err)
	}
	addCmd := []string{"add", filepath.Join(repoPath, utils.LastUpdatedFile)}
	if _, err = utils.Exec("git", append(commandArgs, addCmd...)); err != nil {
		return xerrors.Errorf("error in git add: %w", err)
	}
	amendCmd := []string{"commit", "--amend", "--no-edit"}
	if _, err = utils.Exec("git", append(commandArgs, amendCmd...)); err != nil {
		return xerrors.Errorf("error in git commit --amend: %w", err)
	}
	return nil
}

func sameLastUpdated(a, b utils.LastUpdated) bool {
	if len(a) != len(b) {
		return false
	}
	for key, t := range a {
		if other, ok := b[key]; !ok || !t.Equal(other) {
			return false
		}
	}
	return true
}

func (gc Config) Clean(repoPath string) error {
	commandArgs := generateGitArgs(repoPath)
	resetCmd := []string{"reset", "--hard", "HEAD"}
	if _, err := utils.Exec("git", append(commandArgs, resetCmd...)); err != nil {
		return xerrors.Errorf("git reset error: %w", err)
	}

	cleanCmd := []string{"clean", "-df"}
	if _, err := utils.Exec("git", append(commandArgs, cleanCmd...)); err != nil {
		return xerrors.Errorf("git clean error: %w", err)
	}
	return nil
}

func (gc Config) RemoteBranch(repoPath string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)
	branchCmd := []string{"branch", "--remote"}
	output, err := utils.Exec("git", append(commandArgs, branchCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git branch: %w", err)
	}
	return strings.Split(output, "\n"), nil
}

func (gc Config) Checkout(repoPath string, branch string) error {
	commandArgs := generateGitArgs(repoPath)
	checkoutCmd := []string{"checkout", branch}
	_, err := utils.Exec("git", append(commandArgs, checkoutCmd...))
	if err != nil {
		return xerrors.Errorf("error in git checkout: %w", err)
	}
	return nil
}

func (gc Config) Status(repoPath string) ([]string, error) {
	commandArgs := generateGitArgs(repoPath)

	statusCmd := []string{"status", "--porcelain"}
	output, err := utils.Exec("git", append(commandArgs, statusCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git status: %w", err)
	}
	return strings.Split(strings.TrimSpace(output), "\n"), nil
}

func generateGitArgs(repoPath string) []string {
	gitDir := filepath.Join(repoPath, ".git")
	return []string{"--git-dir", gitDir, "--work-tree", repoPath}
}
