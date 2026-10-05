# `gitlab` role

Installs GitLab at a pinned version on a CIS-hardened RHEL 8 host and configures it as one node
role: every bundled service on one node, or one role of a distributed GitLab. In one converge it:

1. trusts GitLab's package signing key, pinned by fingerprint;
2. installs the pinned `gitlab-fips` package from a copy verified against its SHA-256 on the
   controller **and** on the guest, and against GitLab's signature, immediately before `dnf`
   reads it;
3. writes the first node's `gitlab-secrets.json` when the node has none, the RDS certificate
   bundle on a Rails or Praefect node, and `/etc/gitlab/gitlab.rb`;
4. lets Gitaly execute its runtime binaries under fapolicyd, on a node that runs Gitaly;
5. on the node that migrates a database, creates its service's own database role, its database
   and the extensions, as the database's master user;
6. runs `gitlab-ctl reconfigure`;
7. on a Rails node, installs the shared gitlab-sshd host keys;
8. reads the version, readiness, the services and FIPS mode back from GitLab itself, the gitlab
   rule back from fapolicyd, the fingerprints of gitlab-sshd's host key files, and whether
   Praefect reaches its database.

> **Scope:** `state=absent` is not implemented: the loader fails it by name, because no
> `absent_redhat.yml` exists, until a removal is proven on a live host.

## Node roles

`node_role` selects what the node runs and which inputs it needs.

| `node_role` | Runs | Inputs beyond the installer |
|---|---|---|
| `all-in-one` (default) | PostgreSQL, Redis, Gitaly, Puma, Sidekiq, Workhorse and NGINX | `external_url` |
| `rails` | Puma, Sidekiq, Workhorse, NGINX and gitlab-sshd | `external_url`, `auto_migrate`, `secrets_json`, `monitoring_whitelist`, `database`, `redis.password`, `redis.sentinels`, `redis.sentinel_port`, `redis.sentinel_password`, `gitaly.address` and `gitaly.token` (Praefect's, through the load balancer), `object_store`, `sshd.host_key_source_dir`; on the node that migrates, `database_bootstrap` |
| `gitaly` | Gitaly, one storage of Praefect's virtual storage | `secrets_json`, `gitaly.token` (Praefect's internal token), `gitaly.storage`, `gitaly.internal_api_url` |
| `praefect` | Praefect | `auto_migrate`, `secrets_json`, `database`, `gitaly.token` (the internal token), `praefect.token`, `praefect.nodes`; on the node that migrates, `database_bootstrap` |
| `redis` | Redis and its Sentinel | `secrets_json` (every node but the first), `redis.password`, `redis.sentinel_password`, `redis.primary`, `redis.primary_host` |

`all-in-one` is the degenerate case: a node given no `node_role` renders, byte for byte, the
`gitlab.rb` the single-node deployment's AWS Deploy run proved. No playbook in this repository
deploys it now, so that run is the last that exercised it.

A Rails node names `roles(['application_role'])`. Naming a role stops GitLab's default role from
loading, so the bundled PostgreSQL and Redis stay off with no setting of their own; the
application role's Gitaly is switched off because Gitaly has its own nodes. KAS is switched off:
it would call `external_url`, the load balancer's HTTP listener, whose target a Rails node is.
With client addresses preserved there, a request a node sent to itself through the balancer
would be dropped.

## Gitaly Cluster

A Rails node reaches its repositories only through Praefect, which serves one virtual storage,
`default`, on `praefect.port` (2305) behind the load balancer and replicates every repository to
`praefect.replication_factor` of the Gitaly nodes in `praefect.nodes`. Each Gitaly node holds one
storage, named by `gitaly.storage`.

Two hops take two tokens, which `tasks/validate.yml` requires to differ:

| Hop | Token | Held by |
|---|---|---|
| Gitaly client to Praefect | `praefect.token`; on a Rails node, `gitaly.token` | Rails and Praefect |
| Praefect to Gitaly | `gitaly.token` | Praefect and Gitaly |

A client holding the internal token could reach the Gitaly nodes past Praefect, which GitLab
warns can lose data. The Rails storage carries its token itself, and
`gitlab_rails['gitaly_token']` is deliberately unset, so nothing falls back to a global one.

A Praefect node names no role: none exists for it, so every service GitLab's default role would
start is switched off by name. It connects to its own database, `database.name`, as its own role,
`database.username`, directly and with no PgBouncer between: Praefect opens few connections, and
the connections it holds open for `LISTEN` need a session of their own. The connection is
`verify-full` against the same RDS bundle. The first Praefect node migrates the database
(`auto_migrate`) and the others start once it has. GitLab's firewall table lists a route from
Praefect to GitLab's API on port 80; Praefect 19.4.1 imports no GitLab client, so no such route
is declared.

## Composition and prerequisites

The play runs `credential_resolver`, `host_readiness` and `os_bootstrap` first; the inventory
names the Python 3.12 that bootstrap installs and pipelines every module. The controller needs
read access to the one object the installer key names in the application repository, and no
right to list the bucket. The guest is never given cloud credentials for the package.

With `installer.cache_dir` set, the package is fetched into that controller directory once per
play: the fetch runs once, and only when some host in the play needs the package, not only when
the one host `run_once` happens to pick does. A cache already holding the pinned digest is not
fetched again, and the role never removes it: the playbook owns it. Without `cache_dir`, each
host stages its own controller copy, removed once copied.

## Inputs

See [`meta/main.yml`](meta/main.yml) for every input and [`defaults/main.yml`](defaults/main.yml)
for everything with a safe default. The role composes the object key from the version:
`GitLab Inc/GitLab FIPS/<version>/GitLab-Inc_GitLab-FIPS_<version>-el8_x64.rpm`.

`gitlab.rb` holds credentials and is evaluated by reconfigure as root, so `tasks/validate.yml`
holds every value it carries to a shape that cannot leave its Ruby literal: the URL has no quote,
backslash or whitespace; the database, Redis and Gitaly secrets are 48 or more letters and
digits; addresses, names, the object prefix (`runs/<run id>`) and the allowlist CIDRs are
matched; a copied `secrets_json` must hold every secret the nodes share. No message echoes a
secret.

## Why `gitlab-fips`

The host runs in FIPS mode. GitLab's FIPS package uses the system OpenSSL, where its standard
packages carry their own and run with FIPS off. It is an EE build: without a licence it runs as
the Free tier.

## Shared secrets

Every node must sign and encrypt with the same keys, and a node's first reconfigure generates
whatever it finds missing. `secrets_json`, the content of the first configured node's
`/etc/gitlab/gitlab-secrets.json`, is therefore written before the node's first reconfigure, and
only when the node has none: reconfigure writes back the secrets the node's own `gitlab.rb` sets,
so the file never stays byte-equal to the copy, and replacing it would rewrite it on every
converge. The playbook compares the shared keys on every node afterwards.

## The database

A Rails or Praefect node connects to an external PostgreSQL with `sslmode=verify-full` against
the RDS certificate bundle in `files/`, pinned by its SHA-256: the us-east-1 bundle, which holds
`rds-ca-rsa2048-g1`, the authority a new instance is issued from.

It connects as its service's own role, `database.username`, which holds no superuser, role or
database creation right and owns only its database, `database.name`. GitLab's documentation for
RDS grants its user `rds_superuser` so that it can create extensions; that role could also switch
pgaudit off. Instead, on the one node of each service given `database_bootstrap`, on every
converge and ahead of its reconfigure, the database's master user:

1. reads whether the role, its own membership in the role with INHERIT and SET, and the database
   exist, and creates only what is absent;
2. creates the role with its password as a SCRAM-SHA-256 verifier computed on the host (PBKDF2
   over a random 16-byte salt, Python's standard library), so the password is never sent to the
   database and any logged statement shows only the verifier; the verifier is never set twice;
3. grants the role to itself with INHERIT and SET, which PostgreSQL 16 and later require before
   `CREATE DATABASE ... OWNER`;
4. creates the database, owned by the role, and the extensions (`database_bootstrap.extensions`)
   in its public schema, which the role owns;
5. reads the database again and requires the owner, the membership and every extension.

The master password reaches `psql` only as the first line of its standard input, read into
`PGPASSWORD` by the shell that execs it, with the SQL following on the same input: never argv, a
file or Ansible's `environment` keyword, which lands on the command line `sudo` logs. Every such
task is `no_log`, and `changed` comes from the reads.

## Git over SSH

A Rails node serves git over SSH with gitlab-sshd on `sshd.port` (2222), behind the load
balancer's port 22, never with the host's own sshd. The CIS-hardened sshd, its configuration and
its host keys are untouched, so Ansible's own connection is unaffected. gitlab-sshd offers
FIPS-approved key exchange, ciphers, MACs and host-key algorithms only.

Every Rails node must present the same host keys, or a client that reached one node would refuse
the other. The playbook keeps one ECDSA and one RSA-3072 key under `sshd.host_key_source_dir`, a
root-only directory, on every Rails node. The first reconfigure generates keys of the node's own
and creates the `git` account the keys must belong to, so the role replaces them with the shared
ones after it, content-compared, and restarts gitlab-sshd only when they changed;
`host_keys_glob` loads only the ECDSA and RSA keys. END requires the fingerprints of
gitlab-sshd's key files to equal the shared ones, and an RSA key of at least 3072 bits. An RSA
host key also lets gitlab-sshd offer `ssh-rsa` signatures, which FIPS-mode clients refuse.

## Object storage

A Rails node stores every object type GitLab can consolidate in one bucket, each under
`<prefix>/<type>`, through the instance profile, with downloads proxied through GitLab. Pages is
switched off. The container registry and backups cannot use the consolidated form and are not
configured.

## Reconfigure

| Path | Owner | Why |
|---|---|---|
| `/etc/gitlab/gitlab.rb` | `root`, 0600 | The configuration; reconfigure, as root, is its only reader. It holds credentials, so it is written without a diff |
| `/etc/gitlab/gitlab-secrets.json` | `root`, 0600 | The shared secrets, written only when absent |
| `/etc/gitlab/rds-ca-bundle.pem` | `root`, 0644 | Rails and Praefect: the database's certificate authorities |
| `/var/opt/gitlab/.nwarila-reconfigured` | `root`, 0600 | `<version> <gitlab.rb SHA-256>` of the last successful reconfigure |

`gitlab-ctl reconfigure` runs when the version or `gitlab.rb` differs from the record, and when
the converge rewrote `gitlab.rb`, wrote the shared secrets or changed the certificate bundle. The
record is written after a reconfigure succeeds, so a converged host reports no change and a
failed reconfigure is retried by the next converge. The package's own post-transaction step runs
no reconfigure on a first install: `gitlab.rb` still holds the vendor's placeholder URL then.

## CIS and STIG constraints

| Constraint | How the role meets it |
|---|---|
| fapolicyd | The trust database is refreshed after the package installs, before anything runs it, and again on every converge until a reconfigure is recorded. On a node that runs Gitaly, `rules.d/89-gitlab.rules` adds GitLab's documented rule letting any process execute an ELF under `/var/opt/gitlab/gitaly/`, where Gitaly writes binaries at run time; the rules are loaded whenever `fapolicyd-cli --list` does not show it |
| `noexec` `/tmp`, `/var/tmp`, `/home` | Nothing staged is executed: `rpm` and `dnf` read the package |
| FIPS mode | The FIPS package; END requires OpenSSL in GitLab's Ruby to report FIPS mode. gitlab-sshd offers FIPS-approved algorithms only, and its host keys are ECDSA and RSA-3072 |
| SELinux | Left enforcing; the package labels its own paths |
| No `async` | Reconfigure is bounded by `timeout(1)` in its argv: `async` stages a file fapolicyd denies |
| Database least privilege | Each service's own role, no `rds_superuser`. One node of each service connects as the master user on every converge, ahead of its reconfigure, to read the role, its database and the extensions and to create whatever is absent; the playbook's proof also creates `rds_tools` with it and reads the settings and password types only it may read. Neither service connects as it |

The fapolicyd rule widens what may execute, stated both ways. Before: nothing under
`/var/opt/gitlab/gitaly/` executes unless the RPM database vouches for its digest. After: any
process may execute any ELF placed anywhere in that subtree, because `dir=` matches every
directory below it. The subtree belongs to the `git` account, mode 0700. On a Gitaly node only
Gitaly runs as `git`; on an all-in-one node Puma, Sidekiq and Workhorse, the services behind
GitLab's network listener, do too, so code running as `git` there can write an ELF and execute
it. GitLab documents the rule as required (otherwise a push fails with "pre-receive hook
declined"), and files written at run time cannot be trusted by digest. Rails, Praefect and Redis
nodes never run Gitaly and do not get the rule.

## Redis replication

Each Redis node runs Redis and a Sentinel. The Rails nodes never name a Redis address: Puma,
Sidekiq and Workhorse ask the Sentinels in `redis.sentinels` which node is primary, and ask again
when a connection to it fails other than by timing out, or it answers as a replica. Two
passwords, each a run secret held by the Redis and Rails nodes:

| Password | Presented by | To |
|---|---|---|
| `redis.password` | every Redis client and every replica | Redis |
| `redis.sentinel_password` | every Sentinel client and every peer Sentinel | Sentinel |

`redis.primary` names the node that starts as the primary, and `redis.primary_host` is its
address on every node; the others start as its replicas. That holds for the first start only:
from then on Sentinel decides which node is primary, two of the three Sentinels agreeing. A
reconfigure after a failover keeps the primary Sentinel recorded in `sentinel.conf`, but renders
`redis.conf`'s `replicaof` from `gitlab.rb` again and restarts Redis. The node `redis.primary`
names comes back a primary, and Sentinel demotes it within seconds; a replica Sentinel had
promoted comes back a replica, which leaves no primary until the Sentinels fail over, about 40
seconds. The role reconfigures only when its inputs change, and nothing it is given depends on
which node is primary, so a failover alone triggers no reconfigure.

## State

| State | Does |
|---|---|
| `present` | Everything above |
| `absent` | Not implemented: fails by name |

## Verification

END is ungated: every converge requires the version manifest to begin with the pinned package and
version, `gitlab-ctl status` to report every service `run:`, OpenSSL in GitLab's embedded Ruby to
report FIPS mode, and the record to hold the declared version and the SHA-256 of the `gitlab.rb`
on disk. On an all-in-one or Rails node `/-/readiness?all=1` must answer `ok`, which on a Rails
node proves its database, Redis, and that a Praefect answers through the load balancer: Praefect
answers that health check itself, so the Gitaly nodes are proved by the playbook's
`praefect check`, and the external token by the proof's push; a Praefect node must reach its
database, `praefect sql-ping` printing its OK line; a Rails, Gitaly or Praefect node must be
listening on the port it serves its peers on, and a Redis node on its Redis and Sentinel ports.
With fapolicyd running on a node that runs Gitaly, a fresh `fapolicyd-cli --list` must show the
gitlab rule compiled into the loaded rules file; the proof shows whether it is in force. The
readiness wait and the reconfigure are bounded in `tasks/present_redhat.yml`, and both bounds are
unmeasured until a live run.

The playbook's proof shows the Gitaly Cluster at work: Praefect connects over TLS 1.3 as its own
role and holds its LISTEN connections from every Praefect node; a repository has three current
replicas; with its primary's Gitaly stopped, a push over HTTP succeeds and every repository stays
available; and once the node is back it is reconciled to the same checksum as the other two.
