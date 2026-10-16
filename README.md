# vuln-list-update (AppThreat fork)

AppThreat's fork of [aquasecurity/vuln-list-update](https://github.com/aquasecurity/vuln-list-update).
Fetches vulnerability advisories from upstream sources and publishes them as
JSON files into the [appthreat/vuln-list](https://github.com/appthreat/vuln-list)
repository, which feeds [vulnerability-db](https://github.com/AppThreat/vulnerability-db)
(the `vdb` database) and other consumers.

## Usage

```sh
vuln-list-update -target <target>
```

## Supported targets

| Target | Source | Published tree |
|---|---|---|
| `nvd` | NVD API 2.0 | `api/<year>/CVE-*.json` |
| `alpine` | Alpine issue tracker | `alpine` |
| `alpine-unfixed` | Alpine secfixes tracker | `alpine-unfixed` |
| `amazon` | Amazon Linux ALAS updateinfo | `amazon` |
| `arch-linux` | Arch Linux security tracker | `arch-linux` |
| `bottlerocket` | Bottlerocket updateinfo (`advisories.bottlerocket.aws`) | `bottlerocket` |
| `chainguard` | Chainguard secdb | `chainguard` |
| `debian` | Debian security tracker | `debian` |
| `oracle-oval` | Oracle Linux OVAL (`linux.oracle.com`) | `oval/oracle` |
| `photon` | Photon CVE metadata (`packages.broadcom.com`) | `photon` |
| `redhat` | Red Hat Security Data API (`-years` required) | `redhat` |
| `rocky` | Rocky Linux RLSA updateinfo | `rocky` |
| `seal` | Seal Security feeds (`vulnfeed.sealsecurity.io`) | `seal/{renamed,noprefix}` |
| `suse-cvrf` | SUSE CVRF archive (`ftp.suse.com`) | `cvrf/suse` |
| `ubuntu` | Ubuntu CVE tracker | `ubuntu` |
| `wolfi` | Wolfi secdb | `wolfi` |

`bottlerocket`, `oracle-oval` and `seal` are additions carried by this fork
(ported from upstream aquasecurity PRs #406, #441, #364/#461). Sources whose
data vulnerability-db ingests through OSV feeds instead (osv, github-advisories,
gitlab/glad, kevc, cwe, mariner, minimos, redhat-csaf, eoldates, echo) are
deliberately not carried.

The scheduled workflow in `.github/workflows/update.yml` runs every target on
its own `if: always()` step, retries failed updates three times with a
five-minute delay, and rebases onto the remote before pushing.

## Testing

```sh
go build ./... && go test ./...
```
