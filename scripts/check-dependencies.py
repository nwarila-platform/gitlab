#!/usr/bin/env python3
"""Validate the credential-free dependency declaration contract.

Adapted from nwarila-platform/keycloak's validator, itself adapted from nessus's and from
secure-wazuh's, which introduced the dependencies/ layout. Keycloak's added two closures: the
standing estate the framework consumes but never creates (aws/estate.yml), and the default IAM quota
of ten managed policies per role. Like nessus's, this one closes the playbook against the declared
artifacts, and it adds more: no IAM statement negates an element; the database's parameter group
holds GitLab's required settings and the STIG and CIS hardening that does not conflict with them,
and is the only one the runner may create a database with; the runner reads only its own
database's logs; a host may be launched only with an org EC2 role or GitLab's own instance role;
and the objects bucket is reachable only by that role and the admin role, only under runs/ (the
instance role also under tmp/uploads/, for GitLab's direct-upload temporaries), behind
a bucket policy that only denies. The manifest is checked by shape, so an export rewrites it
without editing this file.
"""

from __future__ import annotations

import fnmatch
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import yaml


REPO_ROOT = Path(__file__).resolve().parent.parent
ROOT = REPO_ROOT / "dependencies"
AWS = ROOT / "aws"
PLAYBOOK = REPO_ROOT / "ansible" / "playbooks" / "gitlab-aws.yml"
ROLE_DEFAULTS = REPO_ROOT / "ansible" / "applications" / "gitlab" / "defaults" / "main.yml"
DEPLOY_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "aws-deploy.yml"

TOKENS = (
    "<account-id>",
    "<owner-id>",
    "<repository-id>",
    "<region>",
    "<vpc-id>",
    "<subnet-id>",
    "<ebs-kms-key-id>",
    "<key-pair-name>",
)
# Absent from the fleet baseline; a document that starts using one must say so here.
ABSENT_TOKENS = (
    "<vpc-id>",
    "<subnet-id>",
    "<ebs-kms-key-id>",
    "<key-pair-name>",
)
# Concrete values that must only ever appear as tokens. The account id is deliberately NOT listed:
# naming it here would publish it. The bare 12-digit scan below catches it without naming it.
FORBIDDEN = (
    "230745524",
    "1348478982",
    "us-east-1",
    "nwarila-ec2-key",
)
# Subnets live only in terraform/aws.tfvars, and the estate names peers by group, never by address.
FORBIDDEN_PATTERNS = (
    re.compile(r"\bvpc-[0-9a-f]{8,17}\b"),
    re.compile(r"\bsubnet-[0-9a-f]{8,17}\b"),
    re.compile(r"\bsg-[0-9a-f]{8,17}\b"),
    re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b"),
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
# Alphanumeric boundaries avoid false positives on 12-digit substrings inside SHA-256 digests.
BARE_ACCOUNT = re.compile(r"(?<![0-9A-Za-z])\d{12}(?![0-9A-Za-z])")
URI = re.compile(r"registry://[A-Za-z0-9._/-]+")
TOKEN = re.compile(r"<[a-z0-9-]+>")

PREFIX = "nwarila-platform_gitlab"
RUNNER_POLICIES = [f"{PREFIX}_runner_{s}" for s in ("ebs", "ec2", "elb", "eni", "iam", "kms", "rds", "s3", "sg", "ssm")]
REAPER_POLICIES = [f"{PREFIX}_reaper_{s}" for s in ("ebs", "ec2", "elb", "eni", "iam", "rds", "s3", "sg")]
# The admin role converges a held bed by hand and never builds the stack: it carries neither elb
# nor rds, only the read of the database's master secret.
ADMIN_POLICIES = [f"{PREFIX}_admin_s3", f"{PREFIX}_admin_secretsmanager"]
# GitLab's own host identity, for the nodes that use object storage.
INSTANCE_ROLE = "nwarila-ec2-gitlab-role"
INSTANCE_POLICY = f"{PREFIX}_instance_s3"
INSTANCE_PROFILES = {"nwarila-ec2-gitlab-profile": [INSTANCE_ROLE]}
POLICY_NAMES = tuple(sorted([*ADMIN_POLICIES, INSTANCE_POLICY, *RUNNER_POLICIES, *REAPER_POLICIES]))
ROLE_ATTACH = {
    INSTANCE_ROLE: [INSTANCE_POLICY],
    f"{PREFIX}_admin": sorted([*ADMIN_POLICIES, *(p for p in RUNNER_POLICIES if not p.endswith(("_elb", "_rds")))]),
    f"{PREFIX}_reaper": REAPER_POLICIES,
    f"{PREFIX}_runner": RUNNER_POLICIES,
}
MANAGED_ATTACH = {INSTANCE_ROLE: ["AmazonSSMManagedInstanceCore"]}
# The one host role that writes S3 reads nothing beyond the fleet's SSM baseline: not the application
# repository, not an S3 secret.
INSTANCE_ATTACHMENTS = {"AmazonSSMManagedInstanceCore", INSTANCE_POLICY}
ROLE_SESSION_SECONDS = {INSTANCE_ROLE: 3600, f"{PREFIX}_admin": 3600, f"{PREFIX}_reaper": 3600, f"{PREFIX}_runner": 7800}
# The organization's EC2 trust, as pdq-deploy-inventory exports nwarila-ec2-apprepo-role's.
EC2_TRUST = {
    "Statement": [
        {
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": "<account-id>"}},
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Sid": "Ec2AssumeForInstanceProfile",
        }
    ],
    "Version": "2012-10-17",
}
# IAM's default "managed policies per role" quota; the account has not been measured above it.
MANAGED_POLICY_QUOTA = 10
EXPORT_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
POLICY_VERSION = re.compile(r"^v[1-9][0-9]*$")

BUCKETS = {
    "registry://aws/s3/apprepo": "<account-id>-apprepo",
}
RESOLVER = {
    "registry://aws/s3/apprepo": {
        "value": "<account-id>-apprepo",
        "evidence": f"dependencies/aws/policies/{PREFIX}_runner_s3.json",
    },
}
APPREPO_WILDCARD = "arn:aws:s3:::<account-id>-apprepo/*"
# The only roles a host of this repository may launch with, and their profiles: a role passed to
# EC2 is the reach of every process on the host.
PASSABLE_ROLES = {
    "arn:aws:iam::<account-id>:role/nwarila-ec2-apprepo-role",
    f"arn:aws:iam::<account-id>:role/{INSTANCE_ROLE}",
    "arn:aws:iam::<account-id>:role/nwarila-ec2-role",
}
READABLE_PROFILES = {
    "arn:aws:iam::<account-id>:instance-profile/nwarila-ec2-apprepo-profile",
    *(f"arn:aws:iam::<account-id>:instance-profile/{profile}" for profile in INSTANCE_PROFILES),
    "arn:aws:iam::<account-id>:instance-profile/nwarila-ec2-profile",
}
PASS_ROLE_CONDITION = {"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}

# GitLab's object storage. Only the instance role and the admin role reach it, only under runs/
# (and tmp/uploads/, below), and only in this account: a same-named bucket elsewhere receives
# nothing.
OBJECTS_BUCKET = "<account-id>-gitlab-objects"
OBJECTS_ARN = f"arn:aws:s3:::{OBJECTS_BUCKET}"
OBJECTS_POLICY = "gitlab-objects.policy.json"
RUN_OBJECT_ACTIONS = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
RUN_ACTIONS = {action.lower() for action in [*RUN_OBJECT_ACTIONS, "s3:ListBucket"]}
RUN_RESOURCES = {OBJECTS_ARN, f"{OBJECTS_ARN}/runs/*"}
# GitLab writes a direct upload's temporary object to tmp/uploads/ at the bucket root whatever the
# bucket prefix, then copies it under the prefix; only the instance role, which GitLab runs as, may.
INSTANCE_RESOURCES = RUN_RESOURCES | {f"{OBJECTS_ARN}/tmp/uploads/*"}
RESOURCE_ACCOUNT = {"aws:ResourceAccount": "<account-id>"}
ADMIN_RUN_SIDS = ["ListGitLabRunPrefix", "ManageGitLabRunObjects"]
OBJECT_PRINCIPALS = [f"arn:aws:iam::<account-id>:role/{INSTANCE_ROLE}", f"arn:aws:iam::<account-id>:role/{PREFIX}_admin"]
# What the bucket policy denies every other principal: object data, versioned or not, and key names.
# It is broader than the grant: S3 authorizes a read or delete that names a version, even the null
# version of an unversioned bucket, as s3:GetObjectVersion or s3:DeleteObjectVersion.
OBJECT_DENY_SID = "DenyObjectDataAndKeyNamesToAllButTheGitLabInstanceAndAdminRoles"
OBJECT_DENY_ACTIONS = {
    "s3:GetObject*",
    "s3:PutObject*",
    "s3:DeleteObject*",
    "s3:AbortMultipartUpload",
    "s3:ListMultipartUploadParts",
    "s3:ListBucket",
    "s3:ListBucketVersions",
    "s3:ListBucketMultipartUploads",
}
# Requests the deny must reach, named so that a narrowed deny says which one it leaves open.
OBJECT_REQUESTS = (
    "s3:GetObject",
    "s3:GetObjectVersion",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:DeleteObjectVersion",
    "s3:AbortMultipartUpload",
    "s3:ListMultipartUploadParts",
    "s3:ListBucket",
    "s3:ListBucketVersions",
    "s3:ListBucketMultipartUploads",
)
# The bucket policy only denies; the identity policies are what grant.
OBJECTS_POLICY_STATEMENTS = {
    "DenyRequestsWithoutTls": {
        "Action": ["s3:*"],
        "Condition": {"Bool": {"aws:SecureTransport": "false"}},
        "Resource": [OBJECTS_ARN, f"{OBJECTS_ARN}/*"],
    },
    OBJECT_DENY_SID: {
        "Action": sorted(OBJECT_DENY_ACTIONS),
        "Condition": {"ArnNotEquals": {"aws:PrincipalArn": OBJECT_PRINCIPALS}},
        "Resource": [OBJECTS_ARN, f"{OBJECTS_ARN}/*"],
    },
}
PUBLIC_ACCESS_BLOCK = ("block_public_acls", "ignore_public_acls", "block_public_policy", "restrict_public_buckets")
APPLY_SCRIPT = REPO_ROOT / "scripts" / "apply-dependencies.sh"
# The IAM actions each S3 operation is authorized as (the Service Authorization Reference), for every
# operation scripts/apply-dependencies.sh calls. head-bucket is recorded because it is the obvious
# existence probe and is authorized as s3:ListBucket, which the bucket policy denies.
S3API_ACTIONS = {
    "create-bucket": ["s3:CreateBucket", "s3:PutBucketOwnershipControls", "s3:TagResource"],
    "get-bucket-encryption": ["s3:GetEncryptionConfiguration"],
    "get-bucket-lifecycle-configuration": ["s3:GetLifecycleConfiguration"],
    "get-bucket-location": ["s3:GetBucketLocation"],
    "get-bucket-ownership-controls": ["s3:GetBucketOwnershipControls"],
    "get-bucket-policy": ["s3:GetBucketPolicy"],
    "get-bucket-tagging": ["s3:GetBucketTagging"],
    "get-bucket-versioning": ["s3:GetBucketVersioning"],
    "get-public-access-block": ["s3:GetBucketPublicAccessBlock"],
    "head-bucket": ["s3:ListBucket"],
    "put-bucket-encryption": ["s3:PutEncryptionConfiguration"],
    "put-bucket-lifecycle-configuration": ["s3:PutLifecycleConfiguration"],
    "put-bucket-ownership-controls": ["s3:PutBucketOwnershipControls"],
    "put-bucket-policy": ["s3:PutBucketPolicy"],
    "put-bucket-tagging": ["s3:PutBucketTagging"],
    "put-public-access-block": ["s3:PutBucketPublicAccessBlock"],
}

ESTATE_TAGS = {"ManagedBy": "apply-dependencies", "Repository": "nwarila-platform/gitlab"}
# The services the runner creates through, each needing its service-linked role first.
SERVICE_LINKED_ROLES = ["elasticloadbalancing.amazonaws.com", "rds.amazonaws.com"]
SYSTEM_SUBNETS = "system-subnets"
DB_PARAMETER_FAMILY = "postgres17"
# The parameter group's exact key set: GitLab's required settings, and the STIG and CIS hardening
# that does not conflict with GitLab (dependencies/README.md maps each to its controls).
DB_PARAMETERS = {
    "client_min_messages",
    "idle_in_transaction_session_timeout",
    "log_connections",
    "log_disconnections",
    "log_error_verbosity",
    "log_line_prefix",
    "log_replication_commands",
    "maintenance_work_mem",
    "max_connections",
    "password_encryption",
    "pgaudit.log",
    "rds.accepted_password_auth_method",
    "rds.force_ssl",
    "shared_buffers",
    "shared_preload_libraries",
    "ssl_min_protocol_version",
    "statement_timeout",
    "work_mem",
}
# GitLab's required settings for an external PostgreSQL (its PostgreSQL tuning guide), as floors in
# the units the RDS API takes: connections, 8 kB pages and kB.
DB_PARAMETER_FLOORS = {"maintenance_work_mem": 65536, "max_connections": 400, "shared_buffers": 262144, "work_mem": 8192}
# GitLab requires a server statement_timeout from 15 to 60 seconds for an external database.
STATEMENT_TIMEOUT_MS = (15000, 60000)
# Held exactly: TLS required, at TLS 1.3 or later, and passwords stored and accepted only as SCRAM.
DB_PARAMETER_VALUES = {
    "password_encryption": "scram-sha-256",
    "rds.accepted_password_auth_method": "scram",
    "rds.force_ssl": "1",
    "ssl_min_protocol_version": "TLSv1.3",
}
PRELOAD_LIBRARIES = {"pg_stat_statements", "pgaudit"}
PGAUDIT_CLASSES = {"ddl", "role"}
# The pgaudit classes that audit GitLab's own queries rather than its schema and roles.
PGAUDIT_QUERY_CLASSES = {"all", "misc", "read", "write"}
# Hardening settings that conflict with GitLab, each refused with the conflict.
DB_PARAMETERS_REFUSED = {
    "idle_session_timeout": "it closes idle sessions, among them Praefect's LISTEN connection and GitLab's pooled connections",
    "log_destination": "RDS manages where logs go, and csvlog doubles their storage",
    "log_file_mode": "RDS manages its log files, and a narrower mode may break their download",
    "log_hostname": "it adds a reverse-DNS lookup to every connection",
    "log_min_duration_statement": "it logs slow statements with their bind values",
    "log_statement": "ddl logs CREATE ROLE ... PASSWORD in cleartext, and mod or all log bind values",
    "pgaudit.log_parameter": "it logs every audited statement's bind values",
    "transaction_timeout": "it bounds whole transactions, and GitLab's long migrations lift only statement_timeout",
}
DIGITS = re.compile(r"^[0-9]+$")
# The deployment reads its own database's logs, and nothing else's.
DATABASE_ARN = "arn:aws:rds:<region>:<account-id>:db:gitlab"
LOG_READ_SID = "ReadTheGitLabDatabaseLogs"
LOG_READ_ACTIONS = ["rds:DescribeDBLogFiles", "rds:DownloadDBLogFilePortion"]


class ContractError(Exception):
    """A dependency contract assertion failed."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ContractError(message)


def rel(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractError(f"JSON parse failed for {rel(path)}: {error}") from error


def load_yaml(path: Path) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as error:
        raise ContractError(f"YAML parse failed for {rel(path)}: {error}") from error


def require_mapping(value: Any, label: str) -> dict[str, Any]:
    require(isinstance(value, dict), f"{label}: expected a mapping")
    return value


def require_keys(value: dict[str, Any], required: set[str], optional: set[str], label: str) -> None:
    actual = set(value)
    require(required <= actual, f"{label}: missing keys {sorted(required - actual)}")
    require(actual <= required | optional, f"{label}: unknown keys {sorted(actual - required - optional)}")


def require_string_list(value: Any, label: str) -> list[str]:
    require(isinstance(value, list), f"{label}: expected a list")
    require(all(isinstance(item, str) for item in value), f"{label}: every entry must be a string")
    require(value == sorted(set(value)), f"{label}: entries must be unique and lexical")
    return value


def as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else [value]


def allows(statement: dict[str, Any], action: str) -> bool:
    """Whether an Allow statement grants the action as IAM matches it: case-insensitively, with wildcards."""
    return statement["Effect"] == "Allow" and any(
        fnmatch.fnmatchcase(action.lower(), pattern.lower()) for pattern in as_list(statement["Action"])
    )


def reaches_objects_bucket(statement: dict[str, Any]) -> bool:
    """Whether an Allow grants an S3 action on the objects bucket, by its name or by a wildcard IAM would match."""
    s3 = any(fnmatch.fnmatchcase("s3", pattern.lower().split(":", 1)[0]) for pattern in as_list(statement["Action"]))
    probes = (OBJECTS_ARN, f"{OBJECTS_ARN}/runs/probe")
    return (
        statement["Effect"] == "Allow"
        and s3
        and any(
            resource.startswith(OBJECTS_ARN) or any(fnmatch.fnmatchcase(probe, resource) for probe in probes)
            for resource in as_list(statement["Resource"])
        )
    )


def policy_paths() -> list[Path]:
    return sorted((AWS / "policies").glob("*.json"))


def statement_paths() -> list[Path]:
    """Every document made of IAM statements: identity policies, trusts and bucket policies."""
    return [*policy_paths(), *sorted((AWS / "roles").glob("*.trust.json")), *sorted((AWS / "buckets").glob("*.json"))]


def json_paths() -> list[Path]:
    """Every JSON document sent to AWS."""
    return [*statement_paths(), *sorted((AWS / "instance-profiles").glob("*.json"))]


def manifest_bytes() -> bytes:
    rows = []
    paths = sorted(
        (path for path in ROOT.rglob("*") if path.is_file() and path.name != "MANIFEST.sha256"),
        key=lambda path: path.relative_to(ROOT).as_posix(),
    )
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        rows.append(f"{digest}  ./{path.relative_to(ROOT).as_posix()}\n")
    return "".join(rows).encode()


def check_integrity() -> None:
    require(ROOT.is_dir(), "dependencies/: directory is missing")
    symlinks = [rel(path) for path in ROOT.rglob("*") if path.is_symlink()]
    require(not symlinks, f"symlink refusal: {symlinks}")
    checksum = subprocess.run(
        ["sha256sum", "-c", "MANIFEST.sha256"],
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    require(
        checksum.returncode == 0,
        "checksum verification failed for (cd dependencies && sha256sum -c MANIFEST.sha256): "
        + (checksum.stdout + checksum.stderr).strip(),
    )
    require(
        (ROOT / "MANIFEST.sha256").read_bytes() == manifest_bytes(),
        "MANIFEST.sha256 differs from deterministic regeneration",
    )


def check_literals_and_tokens() -> None:
    for path in sorted(path for path in ROOT.rglob("*") if path.is_file()):
        text = path.read_text(encoding="utf-8")
        for literal in FORBIDDEN:
            require(literal not in text, f"forbidden concrete literal {literal!r} in {rel(path)}")
        for pattern in FORBIDDEN_PATTERNS:
            match = pattern.search(text)
            require(match is None, f"forbidden concrete identifier {match.group() if match else ''!r} in {rel(path)}")
        match = BARE_ACCOUNT.search(text)
        require(match is None, f"bare 12-digit run {match.group() if match else ''!r} in {rel(path)}")
    corpus = "".join(path.read_text(encoding="utf-8") for path in json_paths())
    observed = set(TOKEN.findall(corpus))
    unknown = observed - set(TOKENS)
    require(not unknown, f"AWS documents contain tokens outside the closed vocabulary: {sorted(unknown)}")
    expected = set(TOKENS) - set(ABSENT_TOKENS)
    require(
        observed == expected,
        "AWS token set differs from the baseline presence record: "
        f"missing={sorted(expected - observed)} unexpectedly_present={sorted(observed - expected)}",
    )


def check_canonical_json() -> None:
    for path in json_paths():
        document = load_json(path)
        expected = (json.dumps(document, indent=2, sort_keys=True) + "\n").encode()
        require(path.read_bytes() == expected, f"canonical JSON serializer mismatch: {rel(path)}")


def check_iam_closures() -> None:
    """No IAM statement negates an element, and only runner_iam passes a role: one a host may launch with, to EC2."""
    for path in statement_paths():
        for statement in load_json(path)["Statement"]:
            label = f"{path.stem} {statement.get('Sid')}"
            negated = sorted({"NotAction", "NotPrincipal", "NotResource"} & set(statement))
            require(not negated, f"{label}: {negated} refused; a negated element covers everything it does not name")
    for path in policy_paths():
        for statement in load_json(path)["Statement"]:
            label = f"{path.stem} {statement.get('Sid')}"
            resources = set(as_list(statement["Resource"]))
            if allows(statement, "iam:PassRole"):
                require(path.stem == f"{PREFIX}_runner_iam", f"{label}: only {PREFIX}_runner_iam may allow iam:PassRole")
                require(
                    resources <= PASSABLE_ROLES,
                    f"{label}: iam:PassRole reaches beyond the EC2 roles a host may launch with: {sorted(resources - PASSABLE_ROLES)}",
                )
                require(
                    statement.get("Condition") == PASS_ROLE_CONDITION,
                    f"{label}: iam:PassRole must carry exactly the condition {PASS_ROLE_CONDITION}",
                )
            if allows(statement, "iam:GetInstanceProfile"):
                require(
                    resources <= READABLE_PROFILES,
                    f"{label}: iam:GetInstanceProfile reaches beyond the EC2 profiles: {sorted(resources - READABLE_PROFILES)}",
                )


def check_declarations() -> dict[str, dict[str, Any]]:
    require(not (AWS / "proposed").exists(), "aws/proposed/ must not exist in the desired-state tree")
    require(
        not (AWS / "profiles").exists(),
        "aws/profiles/ must not exist; this repository's instance profiles live in aws/instance-profiles/",
    )
    profiles = {path.stem: path for path in (AWS / "instance-profiles").glob("*.json")}
    require(set(profiles) == set(INSTANCE_PROFILES), f"aws/instance-profiles/ must hold exactly {sorted(INSTANCE_PROFILES)}")
    for name, path in profiles.items():
        require(
            load_json(path) == {"InstanceProfileName": name, "Roles": INSTANCE_PROFILES[name]},
            f"{rel(path)}: must name itself and hold exactly the role {INSTANCE_PROFILES[name]}",
        )
    policy_json = {path.stem: path for path in (AWS / "policies").glob("*.json")}
    require(not list((AWS / "policies").glob("*.yml")), "policy YAML sidecars are forbidden; metadata belongs in aws/manifest.json")
    require(set(policy_json) == set(POLICY_NAMES), "desired policy JSON set differs from the closed expected set")

    trust_json = {path.name.removesuffix(".trust.json"): path for path in (AWS / "roles").glob("*.trust.json")}
    role_yaml = {path.stem: path for path in (AWS / "roles").glob("*.yml")}
    require(set(trust_json) == set(role_yaml) == set(ROLE_ATTACH), "role trust/YAML pairing is not one-to-one")
    roles = {}
    for name in sorted(role_yaml):
        path = role_yaml[name]
        sidecar = require_mapping(load_yaml(path), rel(path))
        required = {"schema", "name", "session_seconds", "trust", "attach", "managed_attach", "path", "description", "managed_by"}
        require_keys(sidecar, required, set(), rel(path))
        require(sidecar["schema"] == "aws-role/v1", f"{name}: invalid role schema")
        require(sidecar["name"] == name, f"{name}: sidecar name must equal filename stem")
        require(sidecar["trust"] == f"{name}.trust.json", f"{name}: trust must name its paired JSON")
        require(sidecar["session_seconds"] == ROLE_SESSION_SECONDS[name], f"{name}: session_seconds differs from the declared table")
        require(sidecar["path"] == "/" and sidecar["description"] is None, f"{name}: path/description differ from the declared table")
        require(sidecar["managed_by"] == "consumer", f"{name}: managed_by must be consumer")
        attach = require_string_list(sidecar["attach"], f"{name}.attach")
        managed = require_string_list(sidecar["managed_attach"], f"{name}.managed_attach")
        if name == INSTANCE_ROLE:
            require(
                set(attach) | set(managed) == INSTANCE_ATTACHMENTS,
                f"{name}: the host role that writes the objects bucket attaches exactly {sorted(INSTANCE_ATTACHMENTS)}, "
                f"not {sorted(set(attach) | set(managed))}",
            )
            require(load_json(trust_json[name]) == EC2_TRUST, f"{name}: trust differs from the organization's EC2 trust")
        require(attach == ROLE_ATTACH[name], f"{name}: customer-managed attachments differ from the declared table")
        require(managed == MANAGED_ATTACH.get(name, []), f"{name}: AWS-managed attachments differ from the declared table")
        require(
            len(attach) + len(managed) <= MANAGED_POLICY_QUOTA,
            f"{name}: {len(attach) + len(managed)} managed policies exceed the default quota of {MANAGED_POLICY_QUOTA}",
        )
        roles[name] = sidecar
    attached = {policy for attachments in ROLE_ATTACH.values() for policy in attachments}
    require(attached == set(policy_json), "orphan policy file: desired policy attachment closure is incomplete")
    holders = sorted(name for name, sidecar in roles.items() if INSTANCE_POLICY in sidecar["attach"])
    require(holders == [INSTANCE_ROLE], f"only {INSTANCE_ROLE} may attach {INSTANCE_POLICY}; attached by {holders}")
    return roles


def check_manifest(roles: dict[str, dict[str, Any]]) -> None:
    """The manifest is checked by shape, so an export rewrites it without editing this file.

    Before the first export every version is null. After one, every customer-managed version is a
    live version id, except a document added since, which stays null while not_yet_applied lists it.
    """
    manifest = require_mapping(load_json(AWS / "manifest.json"), "aws/manifest.json")
    require(
        list(manifest) == ["exported", "instance_profiles", "roles", "policies", "divergence"],
        "manifest top-level key order/schema is invalid",
    )
    exported = manifest["exported"]
    require(exported is None or EXPORT_DATE.fullmatch(str(exported)) is not None, "manifest exported must be null or a YYYY-MM-DD date")
    require(manifest["instance_profiles"] == INSTANCE_PROFILES, "manifest instance_profiles differ from aws/instance-profiles/")
    divergence = require_mapping(manifest["divergence"], "manifest.divergence")
    require(set(divergence) == {"note", "not_yet_applied"}, "manifest.divergence exact schema violation")
    require(isinstance(divergence["note"], str) and divergence["note"], "manifest.divergence.note must be non-empty")
    pending = require_string_list(divergence["not_yet_applied"], "manifest.divergence.not_yet_applied")
    require(set(pending) <= set(POLICY_NAMES), "manifest.divergence.not_yet_applied names a policy without a real policy JSON")
    require(list(manifest["roles"]) == sorted(roles), "manifest roles must equal sidecars in lexical order")
    for name, sidecar in roles.items():
        role = require_mapping(manifest["roles"][name], f"manifest role {name}")
        require(set(role) == {"attached", "inline"} and role["inline"] == [], f"manifest role {name}: schema or inline policies differ")
        attached = role["attached"]
        require(
            [entry.get("name") for entry in attached] == sorted([*sidecar["attach"], *sidecar["managed_attach"]]),
            f"manifest role {name}: attachments differ from its sidecar",
        )
        for entry in attached:
            policy = entry["name"]
            if policy in sidecar["managed_attach"]:
                require(entry == {"managed_by": "aws", "name": policy}, f"manifest role {name}: AWS-managed {policy} carries no version")
                continue
            require(set(entry) == {"name", "version"}, f"manifest role {name}: {policy} must carry exactly name and version")
            version = entry["version"]
            if exported is None:
                require(version is None, f"manifest role {name}: {policy} records a version, but nothing was exported")
            else:
                require(
                    POLICY_VERSION.fullmatch(str(version)) is not None or (version is None and policy in pending),
                    f"manifest role {name}: {policy} needs its exported version, or null while not_yet_applied lists it",
                )
    policies = require_mapping(manifest["policies"], "manifest.policies")
    require(list(policies) == sorted(POLICY_NAMES), "manifest policies must equal the policy files in lexical order")
    for name, metadata in policies.items():
        expected = {"path": "/", "description": None, "tags": {}, "managed_by": "consumer"}
        require(metadata == expected, f"manifest policy metadata differs from the closed expected table: {name}")


def check_artifacts() -> list[dict[str, Any]]:
    document = require_mapping(load_yaml(AWS / "artifacts.yml"), "aws/artifacts.yml")
    require(set(document) == {"schema", "artifacts", "secrets"}, "aws/artifacts.yml: unknown or missing top-level keys")
    require(document["schema"] == "aws-artifacts/v1", "aws/artifacts.yml: invalid schema")
    objects = []
    for item in document["artifacts"]:
        item = require_mapping(item, "aws/artifacts.yml artifact")
        require_keys(item, {"bucket", "key", "sha256", "access"}, set(), f"artifact {item.get('key')}")
        require(HEX64.fullmatch(str(item["sha256"])) is not None, f"artifact {item['key']}: sha256 must be lowercase 64-hex")
        require(item["access"] == "controller-fetch", f"artifact {item['key']}: access must be controller-fetch")
        objects.append(item)
    for item in document["secrets"]:
        item = require_mapping(item, "aws/artifacts.yml secret")
        require_keys(item, {"bucket", "key", "access"}, set(), f"secret {item.get('key')}")
        require(item["access"] == "controller-secret-lookup", f"secret {item['key']}: access must be controller-secret-lookup")
        objects.append(item)
    for item in objects:
        require(item["bucket"] in BUCKETS, f"{item['key']}: bucket must be a declared registry URI")
    keys = [item["key"] for item in objects]
    require(len(keys) == len(set(keys)), "aws/artifacts.yml declares an object twice")
    return objects


def check_playbook_pins(objects: list[dict[str, Any]]) -> None:
    """The playbook consumes exactly what artifacts.yml declares, at the digests it declares.

    Every play that applies the role is read, so a second node role cannot install another pin.
    """
    installers = [
        role["vars"]["gitlab"]["installer"]
        for play in load_yaml(PLAYBOOK)
        for role in play.get("roles", []) or []
        if isinstance(role, dict) and role.get("role") == "gitlab"
    ]
    require(bool(installers), f"{rel(PLAYBOOK)}: no gitlab role declaration found")
    require(all(item == installers[0] for item in installers), f"{rel(PLAYBOOK)}: the playbook installs different pins in different plays")
    installer = installers[0]
    key_template = load_yaml(ROLE_DEFAULTS)["gitlab_defaults"]["installer"]["key"]
    installer_key = key_template.replace("<version>", str(installer["version"]))
    by_key = {item["key"]: item for item in objects}
    require(installer_key in by_key, f"the playbook installs {installer_key!r}, which artifacts.yml does not declare")
    require(by_key[installer_key]["sha256"] == installer["sha256"], "installer sha256 differs between the playbook and artifacts.yml")
    text = PLAYBOOK.read_text(encoding="utf-8")
    for item in objects:
        if "sha256" not in item:
            require(item["key"] in text, f"secret {item['key']} is declared but the playbook never reads it")


def check_authorization(objects: list[dict[str, Any]]) -> None:
    """The runner may read every declared object and nothing under this repository's prefix."""
    statements = load_json(AWS / "policies" / f"{PREFIX}_runner_s3.json")["Statement"]
    resources: set[str] = set()
    for statement in statements:
        if allows(statement, "s3:GetObject"):
            resources.update(as_list(statement["Resource"]))
    for item in objects:
        arn = f"arn:aws:s3:::{BUCKETS[item['bucket']]}/{item['key']}"
        require(APPREPO_WILDCARD in resources or arn in resources, f"the runner cannot read {item['key']}")
    # Nothing is declared there, so an exact object under the prefix, or a wildcard IAM would match
    # against it (applications/*), is undeclared reach.
    own_prefix = "arn:aws:s3:::<account-id>-ansible/applications/gitlab/"
    reaching = sorted(
        resource
        for statement in statements
        for resource in as_list(statement["Resource"])
        if resource.startswith(own_prefix) or fnmatch.fnmatchcase(own_prefix + "probe", resource)
    )
    require(not reaching, f"{PREFIX}_runner_s3 reaches this repository's prefix, from which nothing is declared: {reaching}")


def check_estate() -> None:
    """The standing estate is closed, names no address, and is what the runner's RDS policy uses.

    Security group rules name their peer by estate group, never by address: membership, not a
    subnet, decides what reaches the load balancer and the database.
    """
    document = require_mapping(load_yaml(AWS / "estate.yml"), "aws/estate.yml")
    require_keys(
        document,
        {"schema", "tags", "service_linked_roles", "db_subnet_groups", "db_parameter_groups", "security_groups", "buckets"},
        set(),
        "aws/estate.yml",
    )
    require(document["schema"] == "aws-estate/v3", "aws/estate.yml: invalid schema")
    require(document["tags"] == ESTATE_TAGS, "aws/estate.yml: tags differ from the closed expected table")
    services = require_string_list(document["service_linked_roles"], "aws/estate.yml service_linked_roles")
    require(services == SERVICE_LINKED_ROLES, "aws/estate.yml: service-linked roles differ from the services the runner creates through")

    rds_policy = (AWS / "policies" / f"{PREFIX}_runner_rds.json").read_text(encoding="utf-8")
    groups = document["db_subnet_groups"]
    require(isinstance(groups, list) and len(groups) == 1, "aws/estate.yml: exactly one DB subnet group is declared")
    group = require_mapping(groups[0], "aws/estate.yml db_subnet_group")
    require_keys(group, {"name", "description", "subnets"}, set(), "aws/estate.yml db_subnet_group")
    require(group["subnets"] == SYSTEM_SUBNETS, f"db_subnet_group {group['name']}: subnets must be {SYSTEM_SUBNETS!r}")
    require(
        f"arn:aws:rds:<region>:<account-id>:subgrp:{group['name']}" in rds_policy,
        f"db_subnet_group {group['name']}: {PREFIX}_runner_rds does not authorize this subnet group",
    )

    names = [require_mapping(sg, "aws/estate.yml security_group").get("name") for sg in document["security_groups"]]
    require(names == sorted(set(names)), "aws/estate.yml: security groups must be unique and lexical by name")
    for sg in document["security_groups"]:
        require_keys(sg, {"name", "description", "ingress", "egress"}, set(), f"security_group {sg['name']}")
        for direction in ("ingress", "egress"):
            require(isinstance(sg[direction], list), f"security_group {sg['name']}.{direction}: expected a list")
            for rule in sg[direction]:
                label = f"security_group {sg['name']}.{direction}"
                rule = require_mapping(rule, label)
                require_keys(rule, {"description", "protocol", "port", "source"}, set(), label)
                require(rule["protocol"] in {"tcp", "udp"}, f"{label}: protocol must be tcp or udp")
                require(isinstance(rule["port"], int) and 0 < rule["port"] < 65536, f"{label}: port must be one port number")
                require(rule["source"] in names, f"{label}: source {rule['source']!r} is not a declared estate security group")
        rules = [(d, rule["protocol"], rule["port"], rule["source"]) for d in ("ingress", "egress") for rule in sg[d]]
        duplicates = sorted({rule for rule in rules if rules.count(rule) > 1})
        require(not duplicates, f"security_group {sg['name']}: rules declared twice, which AWS refuses: {duplicates}")
    check_db_parameter_groups(document["db_parameter_groups"])
    check_bucket(document["buckets"])


def check_db_parameter_groups(groups: Any) -> None:
    """The one parameter group holds GitLab's required settings, and the runner may create a database with no other."""
    require(isinstance(groups, list) and len(groups) == 1, "aws/estate.yml: exactly one DB parameter group is declared")
    group = require_mapping(groups[0], "aws/estate.yml db_parameter_group")
    label = f"db_parameter_group {group.get('name')}"
    require_keys(group, {"name", "family", "description", "parameters"}, set(), label)
    require(group["family"] == DB_PARAMETER_FAMILY, f"{label}: family must be {DB_PARAMETER_FAMILY!r}, not {group['family']!r}")
    parameters = require_mapping(group["parameters"], f"{label} parameters")
    for name in sorted(parameters):
        require(name not in DB_PARAMETERS_REFUSED, f"{label}: {name} is refused: {DB_PARAMETERS_REFUSED.get(name)}")
    require(
        set(parameters) == DB_PARAMETERS,
        f"{label}: parameters must be exactly the declared set; undeclared {sorted(set(parameters) - DB_PARAMETERS)}, "
        f"missing {sorted(DB_PARAMETERS - set(parameters))}",
    )
    require(all(isinstance(value, str) for value in parameters.values()), f"{label}: every value must be a string, as the RDS API takes it")
    numeric = sorted(name for name in [*DB_PARAMETER_FLOORS, "statement_timeout"] if not DIGITS.fullmatch(parameters[name]))
    require(not numeric, f"{label}: {numeric} must be digit strings")
    low = [f"{name} {parameters[name]} < {floor}" for name, floor in sorted(DB_PARAMETER_FLOORS.items()) if int(parameters[name]) < floor]
    require(not low, f"{label}: below GitLab's required floor: {low}")
    timeout = int(parameters["statement_timeout"])
    require(
        STATEMENT_TIMEOUT_MS[0] <= timeout <= STATEMENT_TIMEOUT_MS[1],
        f"{label}: statement_timeout {timeout} is outside GitLab's required {STATEMENT_TIMEOUT_MS[0]}-{STATEMENT_TIMEOUT_MS[1]} ms",
    )
    wrong = [f"{name} {parameters[name]!r}, not {value!r}" for name, value in sorted(DB_PARAMETER_VALUES.items()) if parameters[name] != value]
    require(not wrong, f"{label}: required values differ: {wrong}")
    libraries = {library.strip() for library in parameters["shared_preload_libraries"].split(",")}
    require(
        PRELOAD_LIBRARIES <= libraries,
        f"{label}: shared_preload_libraries must load {sorted(PRELOAD_LIBRARIES)}; missing {sorted(PRELOAD_LIBRARIES - libraries)}",
    )
    classes = {item.strip().lower() for item in parameters["pgaudit.log"].split(",")}
    require(not classes & PGAUDIT_QUERY_CLASSES, f"{label}: pgaudit.log {sorted(classes & PGAUDIT_QUERY_CLASSES)} would audit every GitLab query")
    require(classes <= PGAUDIT_CLASSES, f"{label}: pgaudit.log must be a non-empty subset of {sorted(PGAUDIT_CLASSES)}, not {sorted(classes)}")

    # A create that names, or falls back to, any other group would skip the settings.
    declared = f"arn:aws:rds:<region>:<account-id>:pg:{group['name']}"
    default = f"arn:aws:rds:<region>:<account-id>:pg:default.{DB_PARAMETER_FAMILY}"
    statements = load_json(AWS / "policies" / f"{PREFIX}_runner_rds.json")["Statement"]
    resources = {resource for statement in statements for resource in as_list(statement["Resource"])}
    require(declared in resources, f"{label}: {PREFIX}_runner_rds does not authorize this parameter group")
    others = sorted(
        resource for resource in resources if resource != declared and (":pg:" in resource or fnmatch.fnmatchcase(default, resource))
    )
    require(not others, f"{label}: {PREFIX}_runner_rds reaches other parameter groups, so a create could skip GitLab's settings: {others}")


def check_database_log_reads() -> None:
    """runner_rds reads database logs through one statement: the two log actions, on db:gitlab, scoped as its delete is."""
    statements = load_json(AWS / "policies" / f"{PREFIX}_runner_rds.json")["Statement"]
    delete = next((statement for statement in statements if statement.get("Sid") == "DeleteOwnedDatabaseOnly"), {})
    for statement in statements:
        if not any(allows(statement, action) for action in LOG_READ_ACTIONS):
            continue
        label = f"{PREFIX}_runner_rds {statement.get('Sid')}"
        require(statement.get("Sid") == LOG_READ_SID, f"{label}: only {LOG_READ_SID} may read database logs")
        require(sorted(as_list(statement["Action"])) == LOG_READ_ACTIONS, f"{label}: must grant exactly {LOG_READ_ACTIONS}")
        resources = as_list(statement["Resource"])
        require(resources == [DATABASE_ARN], f"{label}: must reach exactly {DATABASE_ARN}, not {resources}")
        require(
            statement.get("Condition") == delete.get("Condition"),
            f"{label}: must be scoped by the deploy identity exactly as DeleteOwnedDatabaseOnly is",
        )


def check_bucket(buckets: Any) -> None:
    """The objects bucket is private, keyed by S3, owner-enforced, unversioned, and empties itself.

    Expiry must outlast a whole deploy run, every job's timeout summed, or a held run would lose its
    objects.
    """
    require(isinstance(buckets, list) and len(buckets) == 1, "aws/estate.yml: exactly one bucket is declared")
    bucket = require_mapping(buckets[0], "aws/estate.yml bucket")
    label = f"bucket {bucket.get('name')}"
    keys = {"name", "encryption", "public_access_block", "object_ownership", "versioning", "lifecycle", "policy"}
    require_keys(bucket, keys, set(), label)
    require(bucket["name"] == OBJECTS_BUCKET, f"{label}: the objects bucket is {OBJECTS_BUCKET!r}, the name its policies grant on")
    require(bucket["encryption"] == "AES256", f"{label}: encryption must be AES256")
    flags = require_mapping(bucket["public_access_block"], f"{label} public_access_block")
    unset = sorted(flag for flag in PUBLIC_ACCESS_BLOCK if flags.get(flag) is not True)
    require(
        set(flags) == set(PUBLIC_ACCESS_BLOCK) and not unset, f"{label}: public_access_block must set exactly the four flags, all true; unset: {unset}"
    )
    require(bucket["object_ownership"] == "BucketOwnerEnforced", f"{label}: object_ownership must be BucketOwnerEnforced")
    require(bucket["versioning"] is False, f"{label}: versioning must be false, so an expired object is gone")
    lifecycle = require_mapping(bucket["lifecycle"], f"{label} lifecycle")
    require_keys(lifecycle, {"expire_days", "abort_incomplete_multipart_days"}, set(), f"{label} lifecycle")
    expire, abort = lifecycle["expire_days"], lifecycle["abort_incomplete_multipart_days"]
    jobs = load_yaml(DEPLOY_WORKFLOW)["jobs"]
    untimed = sorted(name for name, job in jobs.items() if "timeout-minutes" not in job)
    require(not untimed, f"{label}: {rel(DEPLOY_WORKFLOW)} jobs {untimed} set no timeout-minutes, so no expiry can be shown to outlast the run")
    budget = sum(job["timeout-minutes"] for job in jobs.values())
    require(
        isinstance(expire, int) and expire * 1440 > budget,
        f"{label}: expire_days {expire} must outlast the deploy run's {budget}-minute summed job budget",
    )
    require(isinstance(abort, int) and 1 <= abort <= expire, f"{label}: abort_incomplete_multipart_days must be from 1 to expire_days")
    require(bucket["policy"] == OBJECTS_POLICY, f"{label}: policy must be {OBJECTS_POLICY}")
    present = sorted(path.name for path in (AWS / "buckets").iterdir())
    require(present == [OBJECTS_POLICY], f"aws/buckets/ must hold exactly {OBJECTS_POLICY}, not {present}")


def check_objects_reach() -> None:
    """Only the instance and admin roles reach the objects bucket, under runs/ (instance: tmp/uploads/)."""
    for path in policy_paths():
        statements = load_json(path)["Statement"]
        reaching = [statement for statement in statements if reaches_objects_bucket(statement)]
        sids = sorted(statement.get("Sid") for statement in reaching)
        if path.stem == INSTANCE_POLICY:
            scoped = statements
        elif path.stem == f"{PREFIX}_admin_s3":
            require(sids == ADMIN_RUN_SIDS, f"{path.stem}: only {ADMIN_RUN_SIDS} may reach the objects bucket, not {sids}")
            scoped = reaching
        else:
            require(not reaching, f"{path.stem} {sids}: reaches the objects bucket, which only the instance and admin roles use")
            scoped = []
        for statement in scoped:
            label = f"{path.stem} {statement.get('Sid')}"
            actions = {action.lower() for action in as_list(statement["Action"])}
            require(actions <= RUN_ACTIONS, f"{label}: actions beyond the run-object set: {sorted(actions - RUN_ACTIONS)}")
            resources = set(as_list(statement["Resource"]))
            allowed = INSTANCE_RESOURCES if path.stem == INSTANCE_POLICY else RUN_RESOURCES
            require(resources <= allowed, f"{label}: reaches beyond the bucket's runs/ prefix: {sorted(resources - allowed)}")
            conditions = statement.get("Condition", {})
            require(conditions.get("StringEquals") == RESOURCE_ACCOUNT, f"{label}: must carry exactly StringEquals {RESOURCE_ACCOUNT}")
            if "s3:listbucket" in actions:
                require(
                    conditions.get("StringLike") == {"s3:prefix": ["runs/*"]}, f"{label}: s3:ListBucket must be limited to s3:prefix runs/*"
                )


def check_objects_policy() -> None:
    """The bucket policy only denies: plain HTTP to anyone, and object data and key names to all but the two roles."""
    path = AWS / "buckets" / OBJECTS_POLICY
    statements = load_json(path)["Statement"]
    for statement in statements:
        label = f"{path.name} {statement.get('Sid')}"
        require(statement["Effect"] == "Deny", f"{label}: an Allow is refused; only the identity policies grant on this bucket")
        require(statement.get("Principal") == "*", f"{label}: must apply to Principal '*' and except by condition")
        named = {
            arn
            for operator in statement.get("Condition", {}).values()
            for key, value in operator.items()
            if key.lower() == "aws:principalarn"
            for arn in as_list(value)
        }
        require(
            named <= set(OBJECT_PRINCIPALS),
            f"{label}: names principals other than the instance and admin roles: {sorted(named - set(OBJECT_PRINCIPALS))}",
        )
    deny = next((statement for statement in statements if statement.get("Sid") == OBJECT_DENY_SID), {})
    label = f"{path.name} {OBJECT_DENY_SID}"
    actions = as_list(deny.get("Action", []))
    open_requests = [request for request in OBJECT_REQUESTS if not any(fnmatch.fnmatchcase(request.lower(), a.lower()) for a in actions)]
    require(not open_requests, f"{label}: leaves {open_requests} open to every other principal")
    require(
        set(actions) == OBJECT_DENY_ACTIONS,
        f"{label}: actions differ from the declared deny set: missing {sorted(OBJECT_DENY_ACTIONS - set(actions))}, "
        f"extra {sorted(set(actions) - OBJECT_DENY_ACTIONS)}",
    )
    shape = {
        statement.get("Sid"): {
            "Action": sorted(as_list(statement.get("Action", []))),
            "Condition": statement.get("Condition"),
            "Resource": sorted(as_list(statement.get("Resource", []))),
        }
        for statement in statements
    }
    require(
        len(statements) == len(OBJECTS_POLICY_STATEMENTS) and shape == OBJECTS_POLICY_STATEMENTS,
        f"{path.name}: must be exactly the two Deny statements, {sorted(OBJECTS_POLICY_STATEMENTS)}",
    )


def check_operator_reach() -> None:
    """Every `s3api` call scripts/apply-dependencies.sh makes stays outside the bucket policy's deny.

    The script runs as an account administrator, whom the deny does not except, so an operation the
    deny covers would fail against this tree's own bucket once its policy exists.
    """
    lines = APPLY_SCRIPT.read_text(encoding="utf-8").splitlines()
    code = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
    verbs = re.findall(r"\bs3api ([a-z][a-z0-9-]*)", code)
    require(len(verbs) == code.count("s3api"), f"{rel(APPLY_SCRIPT)}: every s3api call must name its operation literally")
    for verb in sorted(set(verbs)):
        require(verb in S3API_ACTIONS, f"{rel(APPLY_SCRIPT)}: s3api {verb} has no IAM action recorded in S3API_ACTIONS")
        denied = [
            action
            for action in S3API_ACTIONS[verb]
            if any(fnmatch.fnmatchcase(action.lower(), pattern.lower()) for pattern in OBJECT_DENY_ACTIONS)
        ]
        require(
            not denied,
            f"{rel(APPLY_SCRIPT)}: s3api {verb} is authorized as {denied}, which the bucket policy denies the account "
            "administrator this script runs as",
        )


def check_registry_closure() -> None:
    resolver = require_mapping(load_yaml(ROOT / "registry-values.yml"), "registry-values.yml")
    require(resolver == RESOLVER, "registry-values.yml must contain exactly the evidenced resolver entries")
    for uri, entry in resolver.items():
        require((REPO_ROOT / entry["evidence"]).is_file(), f"{uri}: evidence {entry['evidence']} does not exist")
        require(entry["value"] in (REPO_ROOT / entry["evidence"]).read_text(encoding="utf-8"), f"{uri}: evidence does not contain its value")
    used = set()
    for path in sorted(path for path in ROOT.rglob("*") if path.is_file()):
        if path.name in {"registry-values.yml", "README.md"}:
            continue
        used.update(URI.findall(path.read_text(encoding="utf-8")))
    require(used == set(resolver), f"registry URI closure mismatch: used_only={sorted(used - set(resolver))} resolver_only={sorted(set(resolver) - used)}")


def main() -> int:
    try:
        check_integrity()
        check_literals_and_tokens()
        check_canonical_json()
        check_iam_closures()
        roles = check_declarations()
        check_manifest(roles)
        objects = check_artifacts()
        check_playbook_pins(objects)
        check_authorization(objects)
        check_estate()
        check_database_log_reads()
        check_objects_reach()
        check_objects_policy()
        check_operator_reach()
        check_registry_closure()
    except ContractError as error:
        print(f"dependency check failed: {error}", file=sys.stderr)
        return 1
    print(
        "dependency check passed: declarations, metadata, closure, quota, estate, objects bucket, pins, authorization, "
        "literals and integrity are valid"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
