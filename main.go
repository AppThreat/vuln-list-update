package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/appthreat/vuln-list-update/chainguard"
	"github.com/appthreat/vuln-list-update/wolfi"

	"golang.org/x/xerrors"

	"github.com/appthreat/vuln-list-update/alma"
	"github.com/appthreat/vuln-list-update/alpine"
	alpineunfixed "github.com/appthreat/vuln-list-update/alpine-unfixed"
	"github.com/appthreat/vuln-list-update/amazon"
	arch_linux "github.com/appthreat/vuln-list-update/arch"
	"github.com/appthreat/vuln-list-update/debian/tracker"
	"github.com/appthreat/vuln-list-update/git"
	"github.com/appthreat/vuln-list-update/nvd"
	"github.com/appthreat/vuln-list-update/photon"
	"github.com/appthreat/vuln-list-update/redhat/securitydataapi"
	"github.com/appthreat/vuln-list-update/rocky"
	susecvrf "github.com/appthreat/vuln-list-update/suse/cvrf"
	"github.com/appthreat/vuln-list-update/ubuntu"
	"github.com/appthreat/vuln-list-update/utils"
)

const (
	repoURL          = "https://%s@github.com/%s/%s.git"
	defaultRepoOwner = "appthreat"
	defaultRepoName  = "vuln-list"
)

var (
	target = flag.String("target", "", "update target (nvd, alpine, alpine-unfixed, redhat, "+
		"debian, ubuntu, amazon, suse-cvrf, photon, arch-linux, wolfi, chainguard)")
	years        = flag.String("years", "", "update years (only redhat)")
	targetUri    = flag.String("target-uri", "", "alternative repository URI (only glad)")
	targetBranch = flag.String("target-branch", "", "alternative repository branch (only glad)")
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	flag.Parse()
	now := time.Now().UTC()
	gc := &git.Config{}
	debug := os.Getenv("VULN_LIST_DEBUG") != ""

	repoOwner := utils.LookupEnv("VULNLIST_REPOSITORY_OWNER", defaultRepoOwner)
	repoName := utils.LookupEnv("VULNLIST_REPOSITORY_NAME", defaultRepoName)

	// Embed GitHub token to URL
	githubToken := os.Getenv("GITHUB_TOKEN")
	url := fmt.Sprintf(repoURL, githubToken, repoOwner, repoName)

	log.Printf("target repository is %s/%s\n", repoOwner, repoName)
	log.Printf("cloning/pulling into %s", utils.VulnListDir())

	if _, err := gc.CloneOrPull(url, utils.VulnListDir(), "main", debug); err != nil {
		return xerrors.Errorf("clone or pull error: %w", err)
	}

	defer func() {
		if debug {
			return
		}
		log.Println("git reset & clean")
		_ = gc.Clean(utils.VulnListDir())
	}()

	var commitMsg string
	switch *target {
	case "nvd":
		u := nvd.NewUpdater()
		if err := u.Update(); err != nil {
			return xerrors.Errorf("NVD update error: %w", err)
		}
		commitMsg = "NVD"
	case "redhat":
		var yearList []int
		for _, y := range strings.Split(*years, ",") {
			yearInt, err := strconv.Atoi(y)
			if err != nil {
				return xerrors.Errorf("invalid years: %w", err)
			}
			yearList = append(yearList, yearInt)
		}
		if len(yearList) == 0 {
			return xerrors.New("years must be specified")
		}
		if err := securitydataapi.Update(yearList); err != nil {
			return xerrors.Errorf("Red Hat Security Data API update error: %w", err)
		}
		commitMsg = "RedHat " + *years

	case "debian":
		dc := tracker.NewClient()
		if err := dc.Update(); err != nil {
			return xerrors.Errorf("Debian update error: %w", err)
		}
		commitMsg = "Debian Security Bug Tracker"
	case "ubuntu":
		if err := ubuntu.Update(); err != nil {
			return xerrors.Errorf("Ubuntu update error: %w", err)
		}
		commitMsg = "Ubuntu CVE Tracker"
	case "alpine":
		au := alpine.NewUpdater()
		if err := au.Update(); err != nil {
			return xerrors.Errorf("Alpine update error: %w", err)
		}
		commitMsg = "Alpine Issue Tracker"
	case "alpine-unfixed":
		au := alpineunfixed.NewUpdater()
		if err := au.Update(); err != nil {
			return xerrors.Errorf("Alpine Secfixes Tracker update error: %w", err)
		}
		commitMsg = "Alpine Secfixes Tracker"
	case "amazon":
		ac := amazon.NewConfig()
		if err := ac.Update(); err != nil {
			return xerrors.Errorf("Amazon Linux update error: %w", err)
		}
		commitMsg = "Amazon Linux Security Center"

	case "suse-cvrf":
		sc := susecvrf.NewConfig()
		if err := sc.Update(); err != nil {
			return xerrors.Errorf("SUSE CVRF update error: %w", err)
		}
		commitMsg = "SUSE CVRF"
	case "photon":
		pc := photon.NewConfig()
		if err := pc.Update(); err != nil {
			return xerrors.Errorf("Photon update error: %w", err)
		}
		commitMsg = "Photon Security Advisories"

	case "arch-linux":
		al := arch_linux.NewArchLinux()
		if err := al.Update(); err != nil {
			return xerrors.Errorf("Arch Linux update error: %w", err)
		}
		commitMsg = "Arch Linux Security Tracker"
	case "alma":
		ac := alma.NewConfig()
		if err := ac.Update(); err != nil {
			return xerrors.Errorf("AlmaLinux update error: %w", err)
		}
		commitMsg = "AlmaLinux Security Advisory"
	case "rocky":
		rc := rocky.NewConfig()
		if err := rc.Update(); err != nil {
			return xerrors.Errorf("Rocky Linux update error: %w", err)
		}
		commitMsg = "Rocky Linux Security Advisory"

	case "wolfi":
		wu := wolfi.NewUpdater()
		if err := wu.Update(); err != nil {
			return xerrors.Errorf("Wolfi update error: %w", err)
		}
		commitMsg = "Wolfi Security Data"
	case "chainguard":
		cu := chainguard.NewUpdater()
		if err := cu.Update(); err != nil {
			return xerrors.Errorf("Chainguard update error: %w", err)
		}
		commitMsg = "Chainguard Security Data"
	default:
		return xerrors.New("unknown target")
	}

	if debug {
		return nil
	}

	if err := utils.SetLastUpdatedDate(*target, now); err != nil {
		return err
	}

	log.Println("git status")
	files, err := gc.Status(utils.VulnListDir())
	if err != nil {
		return xerrors.Errorf("git status error: %w", err)
	}

	// only last_updated.json
	if len(files) < 2 {
		log.Println("Skip commit and push")
		return nil
	}

	log.Println("git commit")
	if err = gc.Commit(utils.VulnListDir(), "./", commitMsg); err != nil {
		return xerrors.Errorf("git commit error: %w", err)
	}

	log.Println("git push")
	if err = gc.Push(utils.VulnListDir(), "main"); err != nil {
		return xerrors.Errorf("git push error: %w", err)
	}

	return nil
}
