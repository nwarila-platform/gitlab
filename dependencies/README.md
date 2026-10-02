# Dependency declarations

This tree is this repository's declared dependency contract for the organization estates.
`dependencies/aws/` is desired state. Like the keycloak tree it was copied from, it counts as
reconciled against live IAM only once `manifest.json` records an `exported` date. Until then the
manifest records a null export date and null versions rather than claiming an equality nobody
measured; `scripts/apply-dependencies.sh --export` records both. The owner reviews this tree before
any AWS apply.

The layout is the one `nwarila-platform/secure-wazuh` introduced, `nwarila-platform/nessus`
extended, and `nwarila-platform/keycloak` extended again with the standing estate. This tree is
keycloak's, adapted; see "Copy this pattern" below.

## Layout

`aws/policies/` contains one desired customer-managed IAM document per object. Policy metadata
lives in `aws/manifest.json`. There is no `aws/proposed/` tree: desired changes are made in the
real policy files and recorded in the manifest's `divergence` block until they are applied.

`aws/roles/` pairs each desired trust document with a role sidecar. The sidecar carries session
duration, customer and AWS-managed attachments, the trust filename, path, nullable description
and ownership.

`aws/instance-profiles/` holds GitLab's own instance profile, in the golden
`{InstanceProfileName, Roles}` shape. `aws/buckets/` holds the objects bucket's policy; the bucket
itself is declared in `aws/estate.yml`.

`aws/manifest.json` keeps the export date, the profile-to-role mapping and the authoritative
role-to-policy attachments for the closed set: four roles, one instance profile, and twenty-one
customer-managed policies. Its `instance_profiles` block and its AWS-managed attachment entries
follow the golden manifest. Its `policies` and `divergence` objects are declared local extensions
to the golden manifest schema.

`aws/artifacts.yml` declares the exactly consumed S3 objects: the GitLab FIPS package, with its
SHA-256 pin. It declares no secret: GitLab generates its initial root password on the host, and
the playbook reads it there.

`aws/estate.yml` comes from keycloak's tree, extended as schema `aws-estate/v3` with
`db_parameter_groups` and `buckets`. It declares the standing, zero-cost objects the pinned
aws-terraform-framework or GitLab consumes but never creates:
- the RDS and Elastic Load Balancing service-linked roles, which a first create needs;
- the `gitlab` DB subnet group, whose subnets resolve at apply time to the subnets
  `terraform/aws.tfvars` places systems in, so a subnet is named in exactly one file;
- the `gitlab` DB parameter group, family `postgres17`: GitLab's required settings for an external
  PostgreSQL, hardened to the STIG and CIS benchmarks wherever they do not conflict with GitLab.
  "The database parameter group" below lists each value with its controls, and what is
  deliberately not set;
- four security groups. `gitlab-node` is a rule-less membership group every node carries, and
  `gitlab-lb` admits only that group. `gitlab-db-client` is a rule-less membership group only the
  nodes that use the database carry, and `gitlab-db` admits only that group. Reachability is by
  membership, not by address, so nothing else in a shared subnet reaches the load balancer or the
  database. The nodes' own rules are run-scoped and live in `terraform/aws.tfvars`;
- the objects bucket, `<account-id>-gitlab-objects`, for GitLab's object storage. It blocks all
  public access, encrypts with S3-managed keys, enforces bucket ownership (ACLs off) and is never
  versioned. One lifecycle rule over the whole bucket expires every object a day after it is
  written, and aborts an incomplete multipart upload after a day. Its policy only denies: requests
  without TLS, and object data, versioned or not, and key names to every principal except the
  GitLab instance role and the admin role.

There is no `ad/` directory because this repository's Active Directory footprint is empty: the
GitLab nodes join no directory.

## Changes from the fleet baseline

Every document not listed here is the fleet skeleton baseline, renamed to this repository.
`nwarila-platform/keycloak` is the organization's first RDS and load balancer consumer. Its `rds`,
`elb`, `ec2` and Secrets Manager documents are the source of the ones below, adapted to GitLab's
database and network load balancer. The instance role, `instance_s3`, and the additions to
`runner_iam`, `reaper_iam` and `admin_s3` are this repository's own. Unlike Keycloak's, `runner_s3`
is the baseline: the playbook reads no object from the ansible bucket.

**`nwarila-platform_gitlab_runner_rds`** creates, reads and deletes exactly one database,
`gitlab`, and reads its logs and the master secret RDS manages for it.
- Creation requires the deploy identity tags, and also pins the database's shape:
  - engine `postgres`;
  - class `db.t4g.large` (8 GiB), so the 2 GiB of `shared_buffers` is a quarter of memory, the
    usual PostgreSQL sizing. On `db.t4g.medium` it would be half, beside about 200 backends;
  - initial storage at most 20 GiB;
  - storage encrypted;
  - not publicly accessible;
  - master password managed by RDS;
  - not Multi-AZ. The condition is `BoolIfExists`, which admits a single-AZ create whether RDS
    leaves `rds:MultiAz` out of the request context or fills it with false. The provider sends
    Multi-AZ only when it is on. Turning Multi-AZ on is a reviewed edit that drops the condition.

  A plan that drifts from that shape is denied, not billed. Storage autoscaling
  (`max_allocated_storage`) has no condition key, so the database declaration in
  `terraform/aws.tfvars` must keep it disabled.
- The subnet group must be `gitlab`, and the parameter group the tuned `gitlab`, both from
  `estate.yml`. The default option group of PostgreSQL 17 is the only other group it may
  reference, so a create that names the default parameter group is denied. A create that names no
  group falls back to the default; that IAM then evaluates the default, and so denies the create,
  is unproven (see Known gaps).
- Naming the group needs the aws-terraform-framework's `parameter_group_name`
  (aws-terraform-framework#148), which the pin in `.github/terraform-framework-pin` must reach
  before any database is declared. Until then a database create names no group, which leaves it
  to that unproven fallback.
- The runner cannot create, modify or delete the parameter group: it stands, and only this tree
  changes it.
- Deletion requires the identity tags.
- Its logs may be listed and read (`DescribeDBLogFiles`, `DownloadDBLogFilePortion`) only on
  `db:gitlab` and only with the identity tags, as for deletion, so a run reads its own database's
  connection and audit lines and no other database's.
- No snapshot actions are granted. The ephemeral deploy skips the final snapshot, and a grant to
  take one would let a destroy leave billable state behind.
- No `ModifyDBInstance` is granted. The provider calls it while creating only for a non-default
  `ca_cert_identifier`, so the database declaration must leave it null.
- The master secret statements live here, not in a `secretsmanager` policy of their own, because
  they exist only for this database. That also keeps the runner at IAM's default quota of ten
  managed policies.
  - RDS creates the secret through the caller, so `CreateSecret` and `TagResource` are allowed only
    on `rds!db-*` names and only when the call arrives through RDS (`aws:CalledVia`).
  - `GetSecretValue` is allowed only on the secret whose RDS ownership tag names this database,
    matched with the global `aws:ResourceTag` key (see "Measured" below).
- No new KMS grant is needed. Storage uses `aws/rds` and the secret uses `aws/secretsmanager`.
  Naming a separate key for the secret needs the aws-terraform-framework's
  `master_user_secret_kms_alias`, which the pin in `.github/terraform-framework-pin` must reach
  before a database is declared.
  Both are AWS managed keys whose key policies admit the account's principals through their own
  service, and both are free. The `kms:DescribeKey` RDS requires on them comes from the baseline
  `runner_kms`. The provider's alias lookup is itself a DescribeKey, which associates an AWS
  managed key the account has not used before.

**`nwarila-platform_gitlab_runner_elb`** creates and deletes one network load balancer, `gitlab`,
with its listeners and its provider-named (`tf-`) target groups.
- Creation requires the deploy identity tags, and the load balancer must be internal. This
  restates the framework's own rule in the role, so an internet-facing balancer is denied even
  from a modified framework. An application load balancer of the same name is denied.
- Listeners may be created only on the `gitlab` load balancer.
- Tags may be written only during creation.
- Modify, register, deregister, delete and setting security groups require the identity tags.
  The framework turns on inbound-rule enforcement for PrivateLink traffic on every network load
  balancer, and the provider applies it with `SetSecurityGroups` inside the create.
- Describe actions support no resource scoping and are granted on `*`.

**`nwarila-platform_gitlab_runner_ec2`** launches only the `t3.large`, `t3.medium` and `t3.small`
instances the GitLab nodes use. The fleet baseline's tagged-creation statement is split in two:
`ec2:InstanceType` exists on the instance resource and not on the volume, so one statement carrying
it would deny every volume. A tfvars that drifts to a larger size is denied, not billed.

**`nwarila-platform_gitlab_reaper_rds`** and **`nwarila-platform_gitlab_reaper_elb`** are the
destroy-only halves: describe, plus tag-scoped delete and deregister. The reaper keeps no KMS or
Secrets Manager grant. Its destroy runs with `-refresh=false`, and deleting the instance deletes
the managed secret.

**`nwarila-platform_gitlab_admin_secretsmanager`** is the admin role's only new grant: the read
of this database's master secret.

**`nwarila-platform_gitlab_admin`** converges a held bed by hand and never builds the stack. It
therefore carries the baseline runner policies, `admin_s3` and `admin_secretsmanager`, but neither
`runner_elb` nor `runner_rds`. That puts it at the ten-policy quota.

**`nwarila-ec2-gitlab-role`**, with **`nwarila-ec2-gitlab-profile`**, is GitLab's own host
identity, for the nodes that use object storage. Its trust is the organization's EC2 trust, byte for
byte the one `nwarila-ec2-apprepo-role` carries. It attaches exactly `AmazonSSMManagedInstanceCore`
and `nwarila-platform_gitlab_instance_s3`: the one host role that writes S3 reads nothing beyond
the fleet's SSM baseline, neither the application repository nor an S3 secret.

**`nwarila-platform_gitlab_instance_s3`** gets, puts and deletes objects, and aborts and lists
multipart uploads, under `runs/` in the objects bucket, and lists the bucket only under `runs/`.
Every statement requires `aws:ResourceAccount` to be this account, so a bucket of the same name in
another account receives nothing. It grants no `GetBucketLocation` and no
`ListBucketMultipartUploads`. If GitLab needs either, the AccessDenied names it, and the fix is a
reviewed edit here.

**`nwarila-platform_gitlab_runner_iam`** adds reading the GitLab instance profile and passing its
role, only to EC2; the baseline statements are unchanged. **`nwarila-platform_gitlab_reaper_iam`**
adds reading the profile, which the destroy's data source needs, and passes no role.

**`nwarila-platform_gitlab_admin_s3`** adds the same object access and listing under `runs/`, so an
operator can read or clear a held run's objects. It reaches nothing else in the bucket: no object
outside `runs/`, and none of the bucket's configuration or policy.

## The database parameter group

`estate.yml` declares the `gitlab` group, family `postgres17`. Its values are GitLab's required
settings for an external PostgreSQL (GitLab's PostgreSQL tuning guide), hardened to the DISA
Crunchy Data Postgres 16 STIG V1R3, the newest PostgreSQL STIG (there is none for 17), and to the
CIS PostgreSQL 17 Benchmark v1.0.0, wherever they do not conflict with GitLab. Each value is a
string, as the RDS API takes it.

| Parameter | Value | Why |
|---|---|---|
| `max_connections` | `400` | GitLab's minimum; STIG V-261857 |
| `shared_buffers` | `262144` (8 kB pages: 2 GiB) | GitLab's minimum |
| `work_mem` | `8192` (kB: 8 MB) | GitLab |
| `maintenance_work_mem` | `65536` (kB: 64 MB) | GitLab |
| `statement_timeout` | `60000` (ms) | GitLab requires 15000 to 60000, and Rails inherits it; STIG V-261899 |
| `idle_in_transaction_session_timeout` | `60000` (ms) | GitLab's bundled default; STIG V-261910 |
| `password_encryption` | `scram-sha-256` | also the default; STIG V-261891 (CAT I); CIS 5.4 |
| `rds.accepted_password_auth_method` | `scram` | refuses md5 logins; STIG V-261892 (CAT I); CIS 5.4 |
| `rds.force_ssl` | `1` | also the family default; STIG V-261900, V-261932, V-261933; CIS 6.8 |
| `ssl_min_protocol_version` | `TLSv1.3` | CIS 6.9 (v1.0.0) |
| `log_connections` | `1` | STIG V-261866, V-261956, V-261960, V-261961; CIS 3.1.20 |
| `log_disconnections` | `1` | STIG V-261866, V-261960, V-261961; CIS 3.1.21 |
| `log_error_verbosity` | `verbose` | CIS 3.1.22 |
| `log_line_prefix` | `%m:%r:%u@%d:[%p]:%l:%e:%s:%v:%x:%c:%q%a:` (one of the two values RDS accepts) | CIS 3.1.24; STIG V-261860, V-261866, V-261871 |
| `log_replication_commands` | `1` | CIS 7.2 |
| `client_min_messages` | `error` | STIG V-261908, V-261909. Rails sets `warning` for its own sessions |
| `shared_preload_libraries` | `pg_stat_statements,pgaudit` | CIS 3.2 and the STIG's pgaudit rules (below); RDS's default library stays |
| `pgaudit.log` | `ddl,role` | the same controls, for schema and role changes only |

The STIG's pgaudit rules met here are V-261861, V-261865, V-261872, V-261942, V-261944, V-261946,
V-261950, V-261952 and V-261958.

`shared_preload_libraries` takes effect only at boot, which every database does with the group's
values. pgaudit also needs `CREATE EXTENSION pgaudit` in each database, run by its master user;
until then its DDL audit lines lack object names. `ssl_min_protocol_version` refuses any client
that cannot negotiate TLS 1.3. The logs these settings write stay on the instance and end with it.

**Deliberately not set.** The validator refuses each of these, naming the conflict:
- `pgaudit.log` with `read` or `write`, which eleven STIG rules ask for (among them V-261863), or
  `misc` or `all`: it would audit every GitLab query, risking the database's 20 GiB of storage and
  the burstable class's CPU credits;
- `pgaudit.log_parameter`: it logs every audited statement's bind values, such as tokens;
- `log_statement` (CIS 3.1.25): `ddl` logs `CREATE ROLE ... PASSWORD '...'` in cleartext, and
  `mod` or `all` log bind values. pgaudit's `ddl` and `role` classes record the same statements
  with passwords redacted;
- `log_min_duration_statement`: GitLab bundles 1000 ms, but it logs slow statements with their
  bind values;
- `idle_session_timeout`: it closes idle sessions, among them Praefect's LISTEN connection and
  GitLab's pooled connections;
- `transaction_timeout`: it bounds whole transactions, and GitLab's long migrations lift only
  `statement_timeout`;
- `log_hostname`: it adds a reverse-DNS lookup to every connection. Off is also what CIS 3.1.23
  asks for;
- `log_file_mode` and `log_destination`: RDS manages its log files. A narrower mode may break their
  download, and `csvlog` doubles their storage;
- a `statement_timeout` below 15000 ms, such as the STIG's example of 10000: it is under GitLab's
  floor.

## Applying

`scripts/apply-dependencies.sh` is the only apply path. A hand-typed `aws iam` apply once shipped an
unrendered `<region>` token into a live policy (recorded in secure-wazuh's `bootstrap-iam.sh`). Run
it with an administrator profile:

~~~bash
scripts/apply-dependencies.sh [--apply] [--export] [aws-profile]
~~~

Without `--apply` it plans and writes nothing. It exits 0 when live AWS is in sync, 2 when changes
are pending, and 1 on any failure, naming the command that failed. Each run does the following:
- renders every document from live values: the account, the GitHub owner and repository ids, and
  the region;
- refuses any document that still holds a token;
- validates every document with IAM Access Analyzer, and requires that the bucket policy grants
  no public access;
- reports every difference between this tree and live IAM and estate:
  - policy documents;
  - roles: trusts, session durations, attachments, and any undeclared inline policy or
    permissions boundary;
  - the instance profile and the role it holds;
  - service-linked roles;
  - the subnet group;
  - the parameter group: its family, and its user-set parameters as RDS reads them back
    (`describe-db-parameters --source user`). A declared value that differs or is missing is
    written, and a parameter set outside this tree is reset to the family default;
  - security groups with their rules;
  - the objects bucket: its tags, public access block, ownership, encryption, lifecycle and policy,
    each compared on the fields this tree declares.
- refuses to adopt a same-named subnet group, parameter group, security group or bucket that does
  not carry this tree's estate tags. This tree's bucket is tagged in the create call itself, so
  once that is proven live, an untagged one was made by hand;
- refuses a parameter group of another family, which RDS cannot change;
- refuses a bucket name another account holds, and a bucket whose versioning was ever enabled,
  which only a hand edit does and S3 cannot undo. It finds the bucket with `GetBucketLocation`
  given the expected owner, not `HeadBucket`, which is authorized as `s3:ListBucket` and so denied
  to the administrator profile this script runs as.

A failed or throttled read stops the run. It is never taken to mean an object is absent.

With `--apply` it writes those differences in dependency order: service-linked roles, new
policies, roles, the instance profile, the subnet group, the parameter group (created, then each
declared value set, then each undeclared one reset on its own, never the whole group), security
groups, then the bucket and its sub-configurations, and last the new versions of existing policies.
It detaches before it attaches, so a role at its quota can converge. Writing policy versions last
means a widened grant, such as the runner's pass of the instance role, lands only once the bucket
that role writes is fully configured. A write that fails stops the run where it failed. Every write
is idempotent against the next plan, so a re-run converges.

Every parameter write is `ApplyMethod=pending-reboot`, which RDS accepts for static and dynamic
parameters alike: a database boots with the group's values. Apply only between runs. A group
changed while a database is up leaves that database pending a reboot, running the old values.

Once everything has been written, it re-plans and requires no difference. It then simulates each
role against requests its guards must allow and deny:
- the database shape, one condition at a time, with Multi-AZ off, on and unnamed, and a smaller
  and a larger class;
- the parameter group: a create with the tuned group is allowed and with the default group denied,
  the runner can neither create, modify nor delete the group, and the reaper cannot delete it;
- the database's logs: listing and reading them is allowed on this database with its tags, and
  denied on an unowned database and on keycloak's, even with this repository's tags;
- each instance size, the next size up, and a much larger one;
- creating without the deploy identity, and deleting unowned objects;
- the secret, both through RDS and directly, and both this database's and another's;
- the load balancer's scheme and type, setting its security groups, and tagging after creation;
- an escalation probe;
- the reaper's and the admin role's boundaries;
- passing the instance role: to EC2 and not to Lambda, and no other EC2 role; the runner and the
  admin role may, the reaper may not;
- the instance role: object data and listing under `runs/`, and SSM. Outside `runs/`, a listing
  without a prefix, a same-named bucket in another account, the application repository, ansible
  and state buckets, the bucket's configuration, and passing a role are all denied;
- the admin role: objects under `runs/` and listing them, and nothing outside `runs/` or on the
  bucket's configuration. The runner and the reaper reach no object;
- every other repository's runner and admin role, found by listing the account's roles: none may
  pass the instance role or write a run object, and at least one must exist;
- the bucket policy itself, for a caller whose own policy allows the request: the instance and
  admin roles writing and listing `runs/` over TLS are allowed. The same write without TLS, and
  any other repository's role writing, reading the null version, or listing, are explicitly
  denied. Another repository's role, standing in for the account administrator this script runs
  as, may still read every part of the bucket's configuration and replace its policy.

With `--export`, once nothing is pending, it records live IAM in `aws/manifest.json`: today's date
as `exported`, every attached policy's live default version, and an empty `not_yet_applied`. It
regenerates `MANIFEST.sha256` with the command under Integrity, then runs the validator, which must
pass. A blocked estate object does not stop an export, which records IAM only. Commit both files.
Run without `--apply`, `--export` refuses while anything is pending.

Finally it prints what the deployment consumes: the instance profile, the objects bucket, the
security group ids, and the subnet and parameter groups' names once each exists.

The subnet group needs systems in two availability zones. Until `terraform/aws.tfvars` has them, a
plan reports that object as blocked and exits 1, naming how many other changes are pending. An
apply writes everything else first, then exits 1, naming how many changes it applied and verified.

## External dependencies

The Rails node launches with this tree's `nwarila-ec2-gitlab-profile`, which
`terraform/aws.tfvars` selects. Only the nodes that use object storage, Rails and Sidekiq, take it.
The nodes that do not, such as Gitaly, Praefect and Redis, are to launch with the shared
`nwarila-ec2-profile` and its SSM baseline, so none of them can write or delete an object. The
shared profiles are registry-owned and declared by whichever repository owns the shared estate; the
runner holds `iam:PassRole` and `iam:GetInstanceProfile` on them as the fleet baseline grants. The
controller fetches the package, so no node reads the application repository.

The package lives in the shared application repository bucket, under its
`<Publisher>/<Application>/<version>/` layout. The runner already reads that bucket by exact path.

The RDS master secret is not an artifact: RDS creates it with each database and deletes it with
each database, and the runner reads it by the ARN the framework outputs.

The service-linked roles are account-wide. Whichever repository's apply runs first creates them;
every later plan reports them present.

## Registry shim

`registry-values.yml` is the sacrificial local resolver. Delete that one file when the
organization registry exists; declarations retain their URIs. It contains only values genuinely
referenced by machine declarations, in both directions, each with evidence a reader can open in
this repository. Canonical AWS documents are already portable through the token vocabulary. They
therefore keep native AWS ARNs and names and have no resolver entries.

## Integrity

Every file below `dependencies/`, except `MANIFEST.sha256`, is covered by the manifest.
The SHA-256 of `MANIFEST.sha256` is the bundle digest naming the entire declaration set.
Regenerate it from the repository root with exactly:

~~~bash
(cd dependencies && LC_ALL=C find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z \
  | xargs -0 sha256sum > MANIFEST.sha256)
~~~

Verify it with exactly:

~~~bash
(cd dependencies && sha256sum -c MANIFEST.sha256)
~~~

The credential-free validator, `scripts/check-dependencies.py`, also checks:
- schemas, metadata, attachments and object closure;
- tokens, literals, canonical JSON and symlinks, in instance profiles and bucket policies too;
- divergence references;
- the manifest by shape rather than by recorded values, so an export rewrites it without editing
  the validator: before an export every version is null, and after one every customer-managed
  version is a live version id, or null for a document added since while `not_yet_applied` lists
  it. An AWS-managed attachment carries no version;
- that no statement in a policy, trust or bucket policy document uses `NotAction`, `NotResource` or
  `NotPrincipal`;
- that only `runner_iam` allows `iam:PassRole`, and only on the organization's two EC2 roles and
  GitLab's instance role and only to EC2, and that `iam:GetInstanceProfile` reaches only their
  profiles. Actions match as IAM matches them, case-insensitively and with wildcards, so `iam:Pass*`
  and `IAM:passrole` count;
- that `nwarila-ec2-gitlab-profile` is the only instance profile and holds exactly
  `nwarila-ec2-gitlab-role`, whose trust equals the organization's EC2 trust and which attaches
  exactly `AmazonSSMManagedInstanceCore` and `instance_s3`. No other role attaches `instance_s3`;
- that the estate is closed, declares no security group rule twice, names no subnet, VPC,
  security group id or address, and that its subnet group is the one `runner_rds` authorizes;
- that the estate declares exactly one parameter group, of family `postgres17`, with exactly the
  declared keys, as strings: GitLab's floors, a `statement_timeout` from 15000 to 60000 ms,
  passwords only as SCRAM, `rds.force_ssl` at 1 and TLS 1.3, `pg_stat_statements` and `pgaudit`
  preloaded, and a `pgaudit.log` that is a non-empty subset of `ddl,role`. It refuses each
  deliberately unset key by name, and a `pgaudit.log` that would audit every GitLab query;
- that `runner_rds` authorizes that group and reaches no other, by name or by any wildcard IAM
  would match against the default group;
- that `runner_rds` reads database logs only through `ReadTheGitLabDatabaseLogs`: the two log
  actions, on `db:gitlab`, scoped by the deploy identity as its delete is;
- that the objects bucket is declared exactly: all four public access block flags, S3-managed
  encryption, enforced ownership, no versioning, an expiry that outlasts the run's summed job
  budgets (every job's timeout, read from the workflow; a job without one is refused), and a
  multipart abort no later than expiry;
- that only `instance_s3` and two `admin_s3` statements reach the objects bucket, by its name or by
  any wildcard IAM would match against it. Each reaches only the run-object actions under `runs/`,
  in this account, and lists only `runs/*`;
- that the bucket policy is exactly its two Deny statements, applies to every principal, and
  excepts none but the instance and admin roles; that its object deny is exactly the declared
  action set, which is broader than the grant because S3 authorizes a request naming a version,
  even the null version, as a separate action; and it names any object or listing request a
  narrowed deny would leave open;
- that every `s3api` call `scripts/apply-dependencies.sh` makes is authorized as actions outside
  that deny, since the script runs as an account administrator the deny does not except. The
  operations are read from the script, each must name its operation literally, and each is mapped
  to its IAM actions in the validator;
- that each role stays within the default managed-policy quota;
- that every play applying the `gitlab` role installs the same pin, that the pin equals the
  declared artifact, and that the playbook reads every declared secret;
- that the runner's S3 policy authorizes every declared object, and that nothing in it reaches
  this repository's prefix in the ansible bucket.

The documents use `<account-id>`, `<owner-id>`, `<repository-id>` and `<region>`.

## Known gaps

- **Compared with live IAM only once exported.** While `manifest.json` records no `exported` date,
  this repository's live IAM has not been read against this tree. The first plan is that
  comparison: an UPDATE on a document outside `not_yet_applied` means live differs from the fleet
  skeleton, and the tree is reconciled before anything is written. `--export` records the
  comparison once it holds, and its date marks it.
- **A changed invariant.** No host identity in this account could write to S3. Now one host role,
  `nwarila-ec2-gitlab-role`, and one operator role, `nwarila-platform_gitlab_admin`, write one
  bucket, under `runs/`. Every other principal, the account's administrators included, is denied
  that bucket's object data and its key names. The admin role's real audience is the IAM Identity
  Center permission set (`AWSReservedSSO_github_nwarila-platform_*`), the same set that can assume
  every other repository's admin role.
- **Per-run isolation is a convention.** Each run writes below its own prefix under `runs/`, but
  IAM grants the whole of `runs/`, so one run could read or delete another's objects. The deploy's
  concurrency group lets one run at a time hold the bed.
- **Objects outlive the destroy.** Lifecycle cleans `runs/`, not the destroy: an object expires a
  day after it is written, which outlasts the run's summed job budgets. The account-administrator
  profile that applies this tree can configure and inspect the bucket, but cannot list its keys or
  read or write its objects. Emptying the bucket by hand means removing its policy first, or acting
  as the admin role, which reaches `runs/`.
- **No retirement path.** Removing an object from this tree deletes nothing in AWS. Retiring the
  parameter group, the bucket, the profile or the instance role is a separate reviewed change, and
  so is a new parameter-group family: RDS cannot change a group's family, so a new family is a new
  group.
- **Temporary ownership.** This tree is the temporary owner of the instance profile, the bucket,
  the parameter group, and the `aws-estate/v3` and `instance-profiles/` extensions to the
  declaration schema, pending the owner's shared dependency framework. Until then IAM is applied
  by hand, through this script.
- **Inherited SSM reach.** `AmazonSSMManagedInstanceCore` grants `ssm:GetParameter` and
  `ssm:GetParameters` on `*`, as on every fleet host, and the `aws/ssm` key admits the account's
  principals through SSM, so the instance role can also read SecureString parameters. It inherits
  that unchanged.
- **Undeclared bucket sub-resources.** CORS, website, logging and notification configurations are
  neither declared nor inspected. Replication is covered: it requires versioning, which the script
  refuses. With all four public access block flags on, a website or CORS configuration exposes
  nothing publicly, and logging and notifications carry metadata only; each would be set by hand.
- **Not yet proven live.** The following are correct per the AWS Service Authorization Reference
  and the provider's source, but no GitLab run has exercised them yet:
  - `aws:CalledVia` on the RDS-created secret;
  - that RDS tags its secret `aws:rds:primaryDBInstanceArn`;
  - the provider's filtered `DescribeDBInstances` reads against a `db:*` grant;
  - RDS accepting `aws/secretsmanager` named explicitly as the secret's key;
  - the managed secret being deleted with the database;
  - `DescribeDBLogFiles` and `DownloadDBLogFilePortion` matched to the database by its identity
    tags;
  - that a create naming no parameter group is evaluated against `pg:default.postgres17`, and so
    denied. If it is not, such a create runs on the default values, so this guard too would fail
    open. Once the framework pin passes `parameter_group_name`, every run names `gitlab`, so only
    a create that skips it would show this;
  - whether a Multi-AZ create carries `rds:MultiAz`. If it does not, this pin admits Multi-AZ: it
    is the other guard here that fails open. A pair of requests settles it without creating
    anything. They run as a one-off step in an AWS Deploy run dispatched on `main`, the only place
    the runner role can be assumed, before Multi-AZ is enabled and while the `gitlab` subnet group
    does not exist, that is, before the first apply that creates it, which happens once
    `terraform/aws.tfvars` places systems in two zones; afterwards the pair cannot run without
    removing the group, because the control below would create a database.
    - Both are `CreateDBInstance` with the declared shape and every identity request tag, naming
      that subnet group. Only the second adds `--multi-az`.
    - The first is the control. It must fail with `DBSubnetGroupNotFoundFault`, which proves the
      request otherwise passes IAM: the create statement answers AccessDenied for any unmet
      condition, so AccessDenied on the control means the request is wrong and proves nothing.
    - Given that control, AccessDenied on the second means the pin holds, and
      `DBSubnetGroupNotFoundFault` on both means it fails open;
  - `CreateListener` scoped to the network load balancer's ARN;
  - `SetSecurityGroups` inside the network load balancer's create;
  - the provider's `tf-` target group names;
  - the instance role passed through the framework's own launch path.

  Apart from the Multi-AZ pin and the parameter-group fallback, each is a narrowing, so a wrong
  one fails closed as an AccessDenied naming the action. The fix is a reviewed edit here, never a
  wildcard.
- **Measured.** keycloak's first live apply (2026-10-01) found that IAM's policy simulator does not
  evaluate service-prefixed tag keys such as `secretsmanager:ResourceTag/<key>`, even for a plain
  tag, while it does evaluate the global `aws:ResourceTag/<key>`, including for the `aws:`-prefixed
  `aws:rds:primaryDBInstanceArn`. The secret-read statements therefore use the global key: it is
  the key AWS recommends, Secrets Manager supports it for `GetSecretValue`, and the apply's
  simulations can evidence it.
- **Not yet proven live, outside IAM.** These show differently when wrong:
  - the instance profile having propagated before the deploy's `RunInstances` passes it. If it has
    not, the launch fails with an error naming the profile;
  - real S3 applying the bucket's tags from the create's `CreateBucketConfiguration` in
    `<region>`, the one region whose create takes no `LocationConstraint`. If S3 rejects them, the
    create fails and names itself. If S3 accepts them but `GetBucketTagging` does not return them,
    as the local test double did, the next plan refuses this tree's own bucket as untagged. The
    recovery is to write the estate tags by hand with `put-bucket-tagging`, as the owner with the
    administrator profile, then plan again;
  - `GetBucketLocation` answering 403 for a bucket another account holds when given the expected
    owner, and real S3's `NoSuchBucket` error text matching what the script reads as absent. If
    either is wrong, the plan stops on the first call that meets it, and names that call;
  - the shapes S3 reads back, against comparisons on the declared fields, such as whether the
    whole-bucket lifecycle filter reads back as `{}` or as `{"Prefix": ""}`. A shape this tree has
    not seen shows as an UPDATE on every plan, and an `--apply` then fails its re-plan;
  - S3's default `BlockedEncryptionTypes` on a new bucket. The encryption comparison cannot see it,
    so whether the encryption write clears it is unproven.
- **The bucket-policy simulation, settled live (2026-10-02).** The bucket policy is simulated
  with the role under test as the caller and as the `aws:PrincipalArn` its condition reads. The
  simulator accepts a role as the caller and honours `aws:PrincipalArn` given as context: the
  instance role writing over TLS is allowed, and the same write without TLS, or from the deploy
  role, is explicitly denied. `--policy-input-list` must be a JSON list of documents: the CLI
  splits a bare document on its commas, and IAM rejects the pieces as invalid content.
- **The subnet group follows the systems.** `terraform/aws.tfvars` places systems in two
  availability zones, so the plan creates the `gitlab` subnet group over their two subnets. A
  tfvars that placed every system in one zone would leave it blocked again: RDS refuses a subnet
  group in one zone, so every plan would exit 1 on it, naming how many other changes are pending,
  and every `--apply` would exit 1 on it after applying everything else.
- **Network load balancer specifics.** The balancer forwards SSH to gitlab-sshd on port 2222 of
  the nodes, and its SSH target group health-checks HTTP on port 80, so a node whose GitLab is
  stopped leaves both target groups together. The HTTP target group checks its traffic port, and
  so would a Praefect one on 2305. The three egress rules of `gitlab-lb`, 80, 2222 and 2305,
  therefore carry both the traffic and the health checks, and it reaches the nodes on nothing
  else. With client IP preservation, which instance targets have by default, a node sees the
  client's address rather than the balancer's, and a node that reaches itself through the
  balancer is dropped. So no node is both a client and a target of a listener: the Rails nodes,
  the targets, never call the balancer (KAS is off on them, and gitlab-shell and gitlab-sshd reach
  GitLab's internal API locally), and the Gitaly node, its only client, is never a target. The
  balancer's declaration and the nodes' own rules settle both.
- **The parameter group's read shape is unproven.** The local test double reads back exactly the
  parameters this tree set, as strings, and ignores `--source`. If real RDS reads a value back in
  another form, or lists a parameter this tree did not set, every plan shows a MODIFY or a RESET,
  and an `--apply` then fails its re-plan, naming the parameter. The first live apply
  (2026-10-02) settled one case: `--source user` lists `password_encryption` once set, but not
  `rds.force_ssl`, which RDS holds at 1 as a system value. Declared values therefore compare
  against every source; only the reset of parameters this tree did not declare reads the
  user-set ones.
- **Some parameters may not be modifiable on RDS.** Before the first apply, the owner reads
  `aws rds describe-engine-default-parameters --db-parameter-group-family postgres17` for the
  `IsModifiable` and `ApplyType` of `log_line_prefix`, `log_replication_commands`,
  `ssl_min_protocol_version` and `idle_in_transaction_session_timeout`, which the RDS
  documentation does not settle for PostgreSQL 17. A parameter RDS refuses fails its `pg-modify`
  write, which stops the apply and names it.
- **TLS 1.3 is unproven for GitLab's clients.** Whether gitlab-fips's libpq on FIPS RHEL 8
  negotiates TLS 1.3 is unproven. If it does not, the first database connection fails, and the
  fallback is a reviewed edit to `TLSv1.2`.
- **A burstable database class.** GitLab's AWS guidance advises against burstable (`t`) classes
  for its database. `db.t4g.large` is a recorded deviation for short-lived proof runs.
- **Baseline grants this repository does not use.** `runner_s3` grants `s3:GetObject` on the
  domain-join secret and the VPN profile, and on all of `<account-id>-apprepo/*`. `runner_ssm`
  grants `SendCommand` with the PowerShell document. `runner_iam` reads and passes the shared
  `nwarila-ec2-apprepo-profile` and its role, which no GitLab node launches with. These remain in
  the fleet baseline pending a separately reviewed, fleet-wide hardening change.
- **Transitive reach is not declared.** The shared apprepo role and profile, and
  `nwarila-apprepo-read`, are excluded because reach is transitive through `PassRole`, not a
  configured dependency.

## Copy this pattern

The next consumer should:
- declare only the objects it owns;
- keep policy metadata and authoritative attachments in one manifest;
- preserve role sidecars where they carry real data;
- record external shared estate without redeclaring it;
- declare owned standing estate in `estate.yml` with reachability by membership, naming no
  subnet, VPC or address;
- declare an owned instance profile or bucket only with the closures that bound it: the role's
  exact attachments and trust, an exact `PassRole`, a bucket policy that only denies, and every
  other document probed for reach into the bucket;
- close every URI, attachment, token, literal, checksum, divergence reference and passable role in
  its validator.
