# `gitlab` role

Installs GitLab at a pinned version on a CIS-hardened RHEL 8 host, with every bundled service
(PostgreSQL, Redis, Gitaly, Puma, Sidekiq, Workhorse and NGINX) on that one node. In one converge
it:

1. trusts GitLab's package signing key, pinned by fingerprint;
2. installs the pinned `gitlab-fips` package from a copy verified against its SHA-256 on the
   controller **and** on the guest, and against GitLab's signature, immediately before `dnf`
   reads it;
3. writes `/etc/gitlab/gitlab.rb`;
4. lets Gitaly execute its runtime binaries under fapolicyd;
5. runs `gitlab-ctl reconfigure`;
6. reads the version, readiness, the services and FIPS mode back from GitLab itself, and the
   gitlab rule back from fapolicyd.

> **Scope:** one node, reached over HTTP on its private address. The distributed layout, the
> external database, the load balancer and object storage arrive in later stages. `state=absent`
> is not implemented yet: the loader fails it by name, because no `absent_redhat.yml` exists, until
> a stage proves a removal on a live host.

## Composition and prerequisites

The play runs `credential_resolver`, `host_readiness` and `os_bootstrap` first; the inventory
names the Python 3.12 that bootstrap installs and pipelines every module. The controller needs
read access to the one object the installer key names in the application repository, and no
right to list the bucket. The guest is never given cloud credentials.

## Inputs

See [`meta/main.yml`](meta/main.yml) for the required inputs and
[`defaults/main.yml`](defaults/main.yml) for everything with a safe default. The playbook
supplies `installer.bucket`, `installer.version`, `installer.sha256` and `external_url`; the role
composes the object key from the version:
`GitLab Inc/GitLab FIPS/<version>/GitLab-Inc_GitLab-FIPS_<version>-el8_x64.rpm`. The AWS playbook
sets `external_url` to the node's private address, `aws_private_ip_address` from the EC2
inventory. `tasks/validate.yml` requires an `http://` or `https://` URL without quotes or
whitespace, because `gitlab.rb` holds it in a Ruby single-quoted string.

## Why `gitlab-fips`

The host runs in FIPS mode. GitLab's FIPS package uses the system OpenSSL, where its standard
packages carry their own and run with FIPS off. It is an EE build: without a licence it runs as
the Free tier.

## Reconfigure

| Path | Owner | Why |
|---|---|---|
| `/etc/gitlab/gitlab.rb` | `root`, 0600 | The configuration; reconfigure, as root, is its only reader |
| `/var/opt/gitlab/.nwarila-reconfigured` | `root`, 0600 | `<version> <gitlab.rb SHA-256>` of the last successful reconfigure |

`gitlab-ctl reconfigure` runs when the version or `gitlab.rb` differs from the record, and when
the converge rewrote `gitlab.rb`. The record is written after a reconfigure succeeds, so a
converged host reports no change and a failed reconfigure is retried by the next converge. The
package's own post-transaction step runs no reconfigure on a first install: `gitlab.rb` still
holds the vendor's placeholder URL then.

## CIS and STIG constraints

| Constraint | How the role meets it |
|---|---|
| fapolicyd | The trust database is refreshed after the package installs, before anything runs it, and again on every converge until a reconfigure is recorded. `rules.d/89-gitlab.rules` adds GitLab's documented rule letting any process execute an ELF under `/var/opt/gitlab/gitaly/`, where Gitaly writes binaries at run time; the rules are loaded whenever `fapolicyd-cli --list` does not show it |
| `noexec` `/tmp`, `/var/tmp`, `/home` | Nothing staged is executed: `rpm` and `dnf` read the package |
| FIPS mode | The FIPS package; END requires OpenSSL in GitLab's Ruby to report FIPS mode |
| SELinux | Left enforcing; the package labels its own paths |
| No `async` | Reconfigure is bounded by `timeout(1)` in its argv: `async` stages a file fapolicyd denies |

The fapolicyd rule widens what may execute, stated both ways. Before: nothing under
`/var/opt/gitlab/gitaly/` executes unless the RPM database vouches for its digest. After: any
process may execute any ELF placed anywhere in that subtree, because `dir=` matches every
directory below it. The subtree belongs to the `git` account, mode 0700, and Gitaly, Puma,
Sidekiq and Workhorse all run as `git`, the services behind GitLab's network listener among
them: code running as `git` can write an ELF there and execute it, so fapolicyd no longer limits
native execution for that account under that subtree. GitLab documents the rule as required
(otherwise a push fails with "pre-receive hook declined"), and files written at run time cannot
be trusted by digest.

## State

| State | Does |
|---|---|
| `present` | Everything above |
| `absent` | Not implemented: fails by name |

## Verification

END is ungated: every converge requires the version manifest to begin with the pinned package
and version, `/-/readiness?all=1` to answer `ok` for the controller, the database, Redis and
Gitaly, `gitlab-ctl status` then to report every service `run:`, OpenSSL in GitLab's embedded
Ruby to report FIPS mode, and the record to hold the declared version and the SHA-256 of the
`gitlab.rb` on disk. With fapolicyd running, a fresh `fapolicyd-cli --list` must show the gitlab
rule compiled into the loaded rules file; the push proof shows whether it is in force. The
readiness wait and the reconfigure are bounded in `tasks/present_redhat.yml`, and both bounds
are unmeasured until a live run.
