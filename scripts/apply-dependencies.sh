#!/usr/bin/env bash
# =========================================================================================== #
# File: 'scripts/apply-dependencies.sh'
# --- [ Description ] ----------------------------------------------------------------------- #
#
# Plans, and with --apply writes, what dependencies/aws/ declares: this repository's IAM roles,
# policies and instance profile, and the standing estate in estate.yml. With --export it records
# live IAM's versions into dependencies/aws/manifest.json once nothing is pending.
#
#   scripts/apply-dependencies.sh [--apply] [--export] [aws-profile]   (profile defaults to 'admin')
#
# Exit status: 0 in sync (or applied and verified), 2 a plan with pending changes, 1 any failure
# or a blocked estate object. Every failed command stops the run and names itself.
#
# WHY A SCRIPT: a hand-typed `aws iam create-policy-version` once put the literal token `<region>`
# into a live policy, and a read-back diff against the tracked source passed, because the source
# holds that token by design (secure-wazuh scripts/bootstrap-iam.sh). Rendering, the token gate
# and Access Analyzer therefore sit on the only path that writes.
#
# Every value is resolved from a live source, never typed: the account from STS, the owner and
# repository ids from GitHub, and the subnet group's subnets from the systems in
# terraform/aws.tfvars. A write that fails stops the run where it failed; every write is
# idempotent against the next plan, so a re-run converges. After applying, the run re-plans and
# requires no difference, then simulates the roles against requests their guards must allow and
# deny.
#
# =========================================================================================== #
set -euo pipefail

say() { printf '  %-64s %s\n' "$1" "$2"; }
die() { printf 'apply-dependencies: FAIL - %s\n' "$1" >&2; exit 1; }
# One FAIL line per failure, from the shell that owns the step: a subshell (a "$(...)") passes its
# status up without speaking, and the parent names the line that consumed it.
set -E
trap 'rc=$?; ((BASH_SUBSHELL)) && exit "${rc}"; die "line ${LINENO}: ${BASH_COMMAND} exited ${rc}"' ERR

APPLY=false
EXPORT=false
PROFILE='admin'
for arg in "$@"; do
    case "${arg}" in
        --apply) APPLY=true ;;
        --export) EXPORT=true ;;
        -*) die "unknown option ${arg}; usage: scripts/apply-dependencies.sh [--apply] [--export] [aws-profile]" ;;
        *) PROFILE="${arg}" ;;
    esac
done
REGION='us-east-1'
OWNER='nwarila-platform'
REPO='gitlab'
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEP="${ROOT}/dependencies/aws"
TFVARS="${ROOT}/terraform/aws.tfvars"

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT
# Names its own failing call, which the ERR line cannot: it sees only this wrapper, or the last
# command of a pipeline.
aws_() {
    local rc=0
    aws --profile "${PROFILE}" --region "${REGION}" "$@" || rc=$?
    [ "${rc}" -eq 0 ] || printf 'apply-dependencies: aws %s exited %s\n' "$*" "${rc}" >&2
    return "${rc}"
}

# A read that distinguishes an absent object from a failed call: 0 present (output in the file),
# 1 absent. A throttle, a denial or an expired session is not an absent object, and stops the run.
read_or_absent() {
    local out="$1"
    shift
    if aws_ "$@" > "${out}" 2> "${WORK}/stderr"; then return 0; fi
    if grep -q -E -e 'NoSuchEntity|DBSubnetGroupNotFoundFault|DBParameterGroupNotFound' \
            -e 'NoSuchBucket\) when calling the GetBucketLocation operation' \
            -e 'NoSuchTagSet|NoSuchPublicAccessBlockConfiguration|OwnershipControlsNotFoundError' \
            -e 'NoSuchLifecycleConfiguration|NoSuchBucketPolicy|ServerSideEncryptionConfigurationNotFoundError' \
            "${WORK}/stderr"; then
        return 1
    fi
    # Bucket names are global: given the expected owner, GetBucketLocation answers 403 for a name
    # another account holds.
    if grep -q -E '\((403|AccessDenied)\) when calling the GetBucketLocation operation' "${WORK}/stderr"; then
        die "aws $*: the bucket exists and is not ours"
    fi
    die "aws $*: $(cat "${WORK}/stderr")"
}

for tool in aws gh jq python3; do
    command -v "${tool}" > /dev/null || die "${tool} is required"
done

# The tree must satisfy its own credential-free contract before any of it reaches AWS.
python3 "${ROOT}/scripts/check-dependencies.py" > /dev/null || die 'dependencies/ fails scripts/check-dependencies.py'

#region ------ [ Resolve and render ] -------------------------------------------------------- #
echo '== resolving substitution values from live sources =='
ACCOUNT="$(aws_ sts get-caller-identity --query Account --output text)"
OWNER_ID="$(gh api "orgs/${OWNER}" --jq .id)"
REPO_ID="$(gh api "repos/${OWNER}/${REPO}" --jq .id)"
say 'account / region' "${ACCOUNT} / ${REGION}"
say 'GitHub owner id / repository id' "${OWNER_ID} / ${REPO_ID}"

mkdir -p "${WORK}/policies" "${WORK}/roles" "${WORK}/buckets"
cp "${DEP}/policies/"*.json "${WORK}/policies/"
cp "${DEP}/roles/"*.trust.json "${WORK}/roles/"
cp "${DEP}/buckets/"*.json "${WORK}/buckets/"
python3 -c 'import json, sys, yaml; json.dump(yaml.safe_load(open(sys.argv[1])), sys.stdout)' \
    "${DEP}/estate.yml" > "${WORK}/estate.json"
RENDERED=("${WORK}"/policies/*.json "${WORK}"/roles/*.json "${WORK}"/buckets/*.json "${WORK}/estate.json")
sed -i "s|<account-id>|${ACCOUNT}|g; s|<owner-id>|${OWNER_ID}|g; s|<repository-id>|${REPO_ID}|g;
        s|<region>|${REGION}|g" "${RENDERED[@]}"
# The gate the 2026-08-03 incident lacked: a rendered document may hold no token at all.
if leftover="$(grep -l -E '<[a-z0-9-]+>' "${RENDERED[@]}")"; then
    die "unrendered token in: ${leftover//$'\n'/ }"
fi
say 'substitution gate' 'clean'
ESTATE_TAGS_JSON="$(jq -c '[.tags | to_entries[] | {Key: .key, Value: .value}]' "${WORK}/estate.json")"
#endregion --- [ Resolve and render ] -------------------------------------------------------- #

#region ------ [ Validate with Access Analyzer ] --------------------------------------------- #
echo '== validating every document before anything is written =='
for f in "${WORK}"/policies/*.json; do
    # shellcheck disable=SC2016 # backticks are JMESPath literals, not shell
    n="$(aws_ accessanalyzer validate-policy --policy-type IDENTITY_POLICY \
         --policy-document "file://${f}" \
         --query 'length(findings[?findingType==`ERROR`||findingType==`SECURITY_WARNING`])' --output text)"
    [ "${n}" = 0 ] || die "$(basename "${f}") has ${n} error or security finding(s)"
    say "$(basename "${f}")" 'clean'
done
for f in "${WORK}"/roles/*.trust.json; do
    # shellcheck disable=SC2016 # backticks are JMESPath literals, not shell
    n="$(aws_ accessanalyzer validate-policy --policy-type RESOURCE_POLICY \
         --validate-policy-resource-type 'AWS::IAM::AssumeRolePolicyDocument' \
         --policy-document "file://${f}" \
         --query 'length(findings[?findingType==`ERROR`])' --output text)"
    [ "${n}" = 0 ] || die "$(basename "${f}") has ${n} error finding(s)"
    say "$(basename "${f}")" 'clean'
done
for f in "${WORK}"/buckets/*.json; do
    # shellcheck disable=SC2016 # backticks are JMESPath literals, not shell
    n="$(aws_ accessanalyzer validate-policy --policy-type RESOURCE_POLICY \
         --validate-policy-resource-type 'AWS::S3::Bucket' --policy-document "file://${f}" \
         --query 'length(findings[?findingType==`ERROR`||findingType==`SECURITY_WARNING`])' --output text)"
    [ "${n}" = 0 ] || die "$(basename "${f}") has ${n} error or security finding(s)"
    public="$(aws_ accessanalyzer check-no-public-access --resource-type 'AWS::S3::Bucket' \
              --policy-document "file://${f}" --query result --output text)"
    [ "${public}" = PASS ] || die "$(basename "${f}") would grant public access: check-no-public-access answered ${public}"
    say "$(basename "${f}")" 'clean, grants no public access'
done
#endregion --- [ Validate with Access Analyzer ] --------------------------------------------- #

#region ------ [ Plan ] ---------------------------------------------------------------------- #
# IAM does not preserve array order, so documents are compared with every array sorted: order
# carries no meaning in a policy, and an order-sensitive diff reports drift on a correct document.
cat > "${WORK}/same.py" << 'PYEOF'
import json, sys, urllib.parse
def load(path):
    document = json.load(open(path))
    return json.loads(urllib.parse.unquote(document)) if isinstance(document, str) else document
def norm(value):
    if isinstance(value, dict):
        return {key: norm(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return sorted((norm(item) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    return value
sys.exit(0 if norm(load(sys.argv[1]).get("Statement")) == norm(load(sys.argv[2]).get("Statement")) else 1)
PYEOF
same() { python3 -S "${WORK}/same.py" "$1" "$2"; }

ACTIONS="${WORK}/actions"
act() { printf '%s\n' "$*" >> "${ACTIONS}"; }

# Adopting a same-named object someone else made would hand this repository's rules to it.
require_estate_tags() { # label tags-json-file [how such an object arises]
    jq -e --argjson want "${ESTATE_TAGS_JSON}" \
        '[.[] | {Key, Value}] as $have | all($want[]; . as $w | any($have[]; . == $w))' "$2" > /dev/null \
        || die "$1 exists but does not carry this repository's estate tags${3:+ (${3})}; it is not ours to adopt"
}

plan_iam() {
    local name arn role seconds want have names
    local -a inline
    echo '== plan: policies =='
    while read -r name; do
        arn="arn:aws:iam::${ACCOUNT}:policy/${name}"
        if ! read_or_absent "${WORK}/version" iam get-policy --policy-arn "${arn}" \
                --query Policy.DefaultVersionId --output text; then
            say "${name}" 'CREATE'; act policy-create "${name}"; continue
        fi
        # The live default version, which --export records.
        printf '%s\t%s\n' "${name}" "$(< "${WORK}/version")" >> "${WORK}/versions"
        aws_ iam get-policy-version --policy-arn "${arn}" --version-id "$(< "${WORK}/version")" \
            --query PolicyVersion.Document --output json > "${WORK}/live.json"
        if same "${WORK}/live.json" "${WORK}/policies/${name}.json"; then
            say "${name}" "in sync ($(< "${WORK}/version"))"
        else
            say "${name}" "UPDATE (live $(< "${WORK}/version") differs)"; act policy-version "${name}"
        fi
    done < <(jq -r '.policies | keys[]' "${DEP}/manifest.json")

    echo '== plan: roles =='
    while read -r role; do
        seconds="$(sed -n 's/^session_seconds: *\([0-9]*\)$/\1/p' "${DEP}/roles/${role}.yml")"
        have=''
        if ! read_or_absent "${WORK}/role.json" iam get-role --role-name "${role}" --output json; then
            say "${role}" 'CREATE'; act role-create "${role}" "${seconds}"
        else
            jq '.Role.AssumeRolePolicyDocument' "${WORK}/role.json" > "${WORK}/live.json"
            if same "${WORK}/live.json" "${WORK}/roles/${role}.trust.json"; then say "${role} trust" 'in sync'
            else say "${role} trust" 'UPDATE'; act role-trust "${role}"; fi
            if [ "$(jq -r '.Role.MaxSessionDuration' "${WORK}/role.json")" = "${seconds}" ]; then
                say "${role} session" "in sync (${seconds}s)"
            else
                say "${role} session" "UPDATE to ${seconds}s"; act role-session "${role}" "${seconds}"
            fi
            # Declared as none: a boundary or an inline policy would govern the role unseen.
            if jq -e '.Role.PermissionsBoundary' "${WORK}/role.json" > /dev/null; then
                say "${role} boundary" 'REMOVE (not declared)'; act role-boundary-delete "${role}"
            fi
            # Assigned before use: a read inside a process substitution could fail unseen.
            names="$(aws_ iam list-role-policies --role-name "${role}" --query 'PolicyNames[]' --output text)"
            read -r -a inline <<< "${names}"
            for name in "${inline[@]}"; do
                say "${role} inline" "DELETE ${name} (not declared)"; act role-inline-delete "${role}" "${name}"
            done
            have="$(aws_ iam list-attached-role-policies --role-name "${role}" \
                    --query 'AttachedPolicies[].PolicyArn' --output text | tr '\t' '\n' | sort)"
        fi
        want="$(jq -r --arg r "${role}" --arg a "arn:aws:iam::${ACCOUNT}:policy/" \
                '.roles[$r].attached[] | (if .managed_by == "aws" then "arn:aws:iam::aws:policy/" else $a end) + .name' \
                "${DEP}/manifest.json" | sort)"
        while read -r arn; do
            [ -n "${arn}" ] || continue
            say "${role} attach" "ATTACH ${arn##*/}"; act role-attach "${role}" "${arn}"
        done < <(comm -13 <(printf '%s\n' "${have}") <(printf '%s\n' "${want}"))
        while read -r arn; do
            [ -n "${arn}" ] || continue
            say "${role} attach" "DETACH ${arn##*/} (not declared)"; act role-detach "${role}" "${arn}"
        done < <(comm -23 <(printf '%s\n' "${have}") <(printf '%s\n' "${want}"))
    done < <(jq -r '.roles | keys[]' "${DEP}/manifest.json")
}

plan_profiles() {
    local profile role have want
    echo '== plan: instance profiles =='
    while read -r profile; do
        have=''
        if read_or_absent "${WORK}/profile.json" iam get-instance-profile --instance-profile-name "${profile}" --output json; then
            say "instance profile ${profile}" 'present'
            have="$(jq -r '.InstanceProfile.Roles[].RoleName' "${WORK}/profile.json" | sort)"
        else
            say "instance profile ${profile}" 'CREATE'; act profile-create "${profile}"
        fi
        want="$(jq -r --arg p "${profile}" '.instance_profiles[$p][]' "${DEP}/manifest.json" | sort)"
        while read -r role; do
            [ -n "${role}" ] || continue
            say "${profile} role" "REMOVE ${role} (not declared)"; act profile-remove-role "${profile}" "${role}"
        done < <(comm -23 <(printf '%s\n' "${have}") <(printf '%s\n' "${want}"))
        while read -r role; do
            [ -n "${role}" ] || continue
            say "${profile} role" "ADD ${role}"; act profile-add-role "${profile}" "${role}"
        done < <(comm -13 <(printf '%s\n' "${have}") <(printf '%s\n' "${want}"))
    done < <(jq -r '.instance_profiles | keys[]' "${DEP}/manifest.json")
}

plan_estate() {
    local service slr group family declared want have sg_name sg_id rules_want rules_have line key direction name
    echo '== plan: estate =='
    while read -r service; do
        slr="$(aws_ iam list-roles --path-prefix "/aws-service-role/${service}/" --query 'Roles[].RoleName' --output text)"
        if [ -n "${slr}" ]; then
            say "service-linked role for ${service}" 'present'
        else
            say "service-linked role for ${service}" 'CREATE'; act slr-create "${service}"
        fi
    done < <(jq -r '.service_linked_roles[]' "${WORK}/estate.json")

    # The subnet group's subnets are the systems'; the VPC and zones come from AWS.
    mapfile -t SUBNETS < <(grep -E '^[[:space:]]*subnet_id[[:space:]]*=[[:space:]]*"subnet-[0-9a-f]+"' "${TFVARS}" \
                           | grep -oE 'subnet-[0-9a-f]+' | sort -u)
    [ "${#SUBNETS[@]}" -gt 0 ] || die 'terraform/aws.tfvars names no system subnet'
    aws_ ec2 describe-subnets --subnet-ids "${SUBNETS[@]}" \
        --query 'Subnets[].{id:SubnetId,az:AvailabilityZone,vpc:VpcId}' --output json > "${WORK}/subnets.json"
    VPC="$(jq -r '[.[].vpc] | unique | if length == 1 then .[0] else error("the systems span VPCs") end' "${WORK}/subnets.json")"
    say 'system subnets' "${SUBNETS[*]} in ${VPC}"

    while read -r group; do
        if [ "$(jq '[.[].az] | unique | length' "${WORK}/subnets.json")" -lt 2 ]; then
            # RDS refuses a subnet group in one zone; nothing else in the plan depends on it.
            say "DB subnet group ${group}" 'BLOCKED: terraform/aws.tfvars places systems in one availability zone'
            BLOCKED="DB subnet group ${group} needs systems in two availability zones"
        elif read_or_absent "${WORK}/sng.json" rds describe-db-subnet-groups --db-subnet-group-name "${group}" --output json; then
            DB_SUBNET_GROUP="${group}"
            aws_ rds list-tags-for-resource --resource-name "$(jq -r '.DBSubnetGroups[0].DBSubnetGroupArn' "${WORK}/sng.json")" \
                --query TagList --output json > "${WORK}/tags.json"
            require_estate_tags "DB subnet group ${group}" "${WORK}/tags.json"
            if [ "$(jq -r '.DBSubnetGroups[0].Subnets[].SubnetIdentifier' "${WORK}/sng.json" | sort)" = "$(printf '%s\n' "${SUBNETS[@]}")" ]; then
                say "DB subnet group ${group}" 'in sync'
            else
                say "DB subnet group ${group}" 'UPDATE subnets'; act subnetgroup-modify "${group}"
            fi
        else
            say "DB subnet group ${group}" 'CREATE'; act subnetgroup-create "${group}"
        fi
    done < <(jq -r '.db_subnet_groups[].name' "${WORK}/estate.json")

    # A parameter group is compared by reading its user-set parameters: a declared value that
    # differs or is missing is written, and one set outside this tree is reset to the family default.
    while read -r group; do
        have=''
        in_force=''
        if ! read_or_absent "${WORK}/pg.json" rds describe-db-parameter-groups --db-parameter-group-name "${group}" --output json; then
            say "DB parameter group ${group}" 'CREATE'; act pg-create "${group}"
        else
            aws_ rds list-tags-for-resource --resource-name "$(jq -r '.DBParameterGroups[0].DBParameterGroupArn' "${WORK}/pg.json")" \
                --query TagList --output json > "${WORK}/tags.json"
            require_estate_tags "DB parameter group ${group}" "${WORK}/tags.json"
            family="$(jq -r '.DBParameterGroups[0].DBParameterGroupFamily' "${WORK}/pg.json")"
            declared="$(jq -r --arg n "${group}" '.db_parameter_groups[] | select(.name == $n) | .family' "${WORK}/estate.json")"
            [ "${family}" = "${declared}" ] \
                || die "DB parameter group ${group} is ${family}, not ${declared}: family is immutable; retirement is a separate reviewed change"
            DB_PARAMETER_GROUP="${group}"
            say "DB parameter group ${group}" "present (${family})"
            have="$(aws_ rds describe-db-parameters --db-parameter-group-name "${group}" --source user --output json \
                    | jq -r '.Parameters[] | "\(.ParameterName)=\(.ParameterValue)"' | sort)"
            # A declared value RDS already holds as a system value (rds.force_ssl on postgres17) is never
            # listed as user-set, so declared values compare against every source.
            in_force="$(aws_ rds describe-db-parameters --db-parameter-group-name "${group}" --output json \
                    | jq -r '.Parameters[] | "\(.ParameterName)=\(.ParameterValue)"' | sort)"
        fi
        want="$(jq -r --arg n "${group}" '.db_parameter_groups[] | select(.name == $n) | .parameters | to_entries[]
                | "\(.key)=\(.value)"' "${WORK}/estate.json" | sort)"
        while read -r key; do
            [ -n "${key}" ] || continue
            say "  ${group}" "MODIFY ${key}"; act pg-modify "${group}" "${key%%=*}"
        done < <(comm -13 <(printf '%s\n' "${in_force}") <(printf '%s\n' "${want}"))
        while read -r name; do
            [ -n "${name}" ] || continue
            say "  ${group}" "RESET ${name} (not declared)"; act pg-reset "${group}" "${name}"
        done < <(comm -23 <(printf '%s\n' "${have}" | cut -d= -f1) <(printf '%s\n' "${want}" | cut -d= -f1))
    done < <(jq -r '.db_parameter_groups[].name' "${WORK}/estate.json")

    # Estate groups by name. A rule's peer renders as sg:<name> when it is one of them, so desired
    # and live rules compare before any group id exists.
    aws_ ec2 describe-security-groups --filters "Name=vpc-id,Values=${VPC}" \
        "Name=group-name,Values=$(jq -r '[.security_groups[].name] | join(",")' "${WORK}/estate.json")" \
        --query 'SecurityGroups[].{name:GroupName,id:GroupId,tags:Tags}' --output json > "${WORK}/sgs.json"
    SG_IDS=()
    while read -r sg_name sg_id; do
        SG_IDS["${sg_name}"]="${sg_id}"
    done < <(jq -r '.[] | "\(.name) \(.id)"' "${WORK}/sgs.json")
    while read -r sg_name; do
        rules_want="$(jq -r --arg n "${sg_name}" '.security_groups[] | select(.name == $n) as $sg
            | ["ingress", "egress"][] as $d | $sg[$d][] | "\($d) \(.protocol) \(.port)-\(.port) sg:\(.source)"' \
            "${WORK}/estate.json" | sort)"
        rules_have=''
        : > "${WORK}/rules-${sg_name}"
        sg_id="$(jq -r --arg n "${sg_name}" '.[] | select(.name == $n) | .id' "${WORK}/sgs.json")"
        if [ -z "${sg_id}" ]; then
            say "security group ${sg_name}" 'CREATE'; act sg-create "${sg_name}"
        else
            jq --arg n "${sg_name}" '.[] | select(.name == $n) | .tags // []' "${WORK}/sgs.json" > "${WORK}/tags.json"
            require_estate_tags "security group ${sg_name}" "${WORK}/tags.json"
            say "security group ${sg_name}" "present (${sg_id})"
            # One line per live rule: its comparison key, a tab, then its id for a revoke.
            aws_ ec2 describe-security-group-rules --filters "Name=group-id,Values=${sg_id}" --output json \
              | jq -r --slurpfile sgs "${WORK}/sgs.json" '.SecurityGroupRules[]
                  | (.ReferencedGroupInfo.GroupId // null) as $ref
                  | ([$sgs[0][] | select(.id == $ref) | "sg:" + .name][0]
                     // $ref // .CidrIpv4 // .CidrIpv6 // .PrefixListId) as $peer
                  | "\(if .IsEgress then "egress" else "ingress" end) \(.IpProtocol)"
                    + " \(if .IpProtocol == "-1" then "all" else "\(.FromPort)-\(.ToPort)" end) \($peer)"
                    + "\t\(.SecurityGroupRuleId)"' > "${WORK}/rules-${sg_name}"
            rules_have="$(cut -f1 "${WORK}/rules-${sg_name}" | sort)"
        fi
        while read -r key; do
            [ -n "${key}" ] || continue
            say "  ${sg_name}" "AUTHORIZE ${key}"; act sg-authorize "${sg_name}" "${key}"
        done < <(comm -13 <(printf '%s\n' "${rules_have}") <(printf '%s\n' "${rules_want}"))
        while read -r key; do
            [ -n "${key}" ] || continue
            line="$(grep -F -m1 "${key}"$'\t' "${WORK}/rules-${sg_name}")"
            direction="${key%% *}"
            say "  ${sg_name}" "REVOKE ${key}"; act sg-revoke "${sg_name}" "${direction}" "${line#*$'\t'}"
        done < <(comm -23 <(printf '%s\n' "${rules_have}") <(printf '%s\n' "${rules_want}"))
    done < <(jq -r '.security_groups[].name' "${WORK}/estate.json")
}

# One declared sub-configuration of a bucket, in the shape its put call takes.
bucket_want() { # bucket sub-configuration
    jq -c --arg n "$1" --arg s "$2" --argjson tags "${ESTATE_TAGS_JSON}" '.buckets[] | select(.name == $n) | {
        "tags": {TagSet: $tags},
        "public-access-block": (.public_access_block | {BlockPublicAcls: .block_public_acls,
            IgnorePublicAcls: .ignore_public_acls, BlockPublicPolicy: .block_public_policy,
            RestrictPublicBuckets: .restrict_public_buckets}),
        "ownership": {Rules: [{ObjectOwnership: .object_ownership}]},
        "encryption": {Rules: [{ApplyServerSideEncryptionByDefault: {SSEAlgorithm: .encryption}}]},
        "lifecycle": {Rules: [{ID: "expire-every-object", Status: "Enabled", Filter: {Prefix: ""},
            Expiration: {Days: .lifecycle.expire_days},
            AbortIncompleteMultipartUpload: {DaysAfterInitiation: .lifecycle.abort_incomplete_multipart_days}}]}
    }[$s]' "${WORK}/estate.json"
}

plan_buckets() {
    local bucket sub norm status policy
    local -a get
    echo '== plan: buckets =='
    while read -r bucket; do
        # GetBucketLocation, not HeadBucket: HeadBucket is authorized as s3:ListBucket, which the
        # bucket policy denies this apply's own administrator profile.
        if ! read_or_absent "${WORK}/location.json" s3api get-bucket-location --bucket "${bucket}" \
                --expected-bucket-owner "${ACCOUNT}"; then
            # The create also writes the tags and the object ownership.
            say "bucket ${bucket}" 'CREATE'; act bucket-create "${bucket}"
            for sub in public-access-block encryption lifecycle policy; do
                say "  ${bucket}" "PUT ${sub}"; act "bucket-${sub}" "${bucket}"
            done
            continue
        fi
        read_or_absent "${WORK}/tagging.json" s3api get-bucket-tagging --bucket "${bucket}" \
            --expected-bucket-owner "${ACCOUNT}" --output json || echo '{"TagSet": []}' > "${WORK}/tagging.json"
        jq '.TagSet' "${WORK}/tagging.json" > "${WORK}/tags.json"
        require_estate_tags "bucket ${bucket}" "${WORK}/tags.json" 'made by hand'
        say "bucket ${bucket}" 'present'
        # A bucket never returns to unversioned, and with versioning expiry keeps noncurrent versions.
        status="$(aws_ s3api get-bucket-versioning --bucket "${bucket}" --expected-bucket-owner "${ACCOUNT}" \
                  --query Status --output text)"
        [ "${status}" = None ] || die "bucket ${bucket} has versioning ${status}, which only a hand edit sets; empty, delete and re-create it"

        if jq -e --argjson want "$(bucket_want "${bucket}" tags)" \
                '(.TagSet | sort_by(.Key)) == ($want.TagSet | sort_by(.Key))' "${WORK}/tagging.json" > /dev/null; then
            say "  ${bucket} tags" 'in sync'
        else
            say "  ${bucket} tags" 'UPDATE'; act bucket-tags "${bucket}"
        fi
        # Each live sub-configuration is read into the shape its put call takes, and compared on
        # what the declaration sets: S3 adds fields of its own, such as BucketKeyEnabled.
        for sub in public-access-block ownership encryption lifecycle; do
            case "${sub}" in
                public-access-block) get=(s3api get-public-access-block --query PublicAccessBlockConfiguration); norm='.' ;;
                ownership) get=(s3api get-bucket-ownership-controls --query OwnershipControls); norm='.' ;;
                encryption) get=(s3api get-bucket-encryption --query ServerSideEncryptionConfiguration)
                    norm='[.Rules[].ApplyServerSideEncryptionByDefault | {SSEAlgorithm, KMSMasterKeyID}]' ;;
                # A whole-bucket filter may read back as {} rather than {"Prefix": ""}. Transitions and
                # noncurrent-version rules are declared absent, so one added by hand is a difference.
                lifecycle) get=(s3api get-bucket-lifecycle-configuration --query '{Rules: Rules}')
                    norm='[.Rules[] | {Status, Filter: (.Filter // {} | with_entries(select(.value != ""))),
                           Days: .Expiration.Days, Abort: .AbortIncompleteMultipartUpload.DaysAfterInitiation,
                           Transitions: (.Transitions // []), NoncurrentVersionTransitions: (.NoncurrentVersionTransitions // []),
                           NoncurrentVersionExpiration}]' ;;
            esac
            if read_or_absent "${WORK}/live.json" "${get[@]}" --bucket "${bucket}" \
                    --expected-bucket-owner "${ACCOUNT}" --output json \
                && jq -e -n --slurpfile live "${WORK}/live.json" --argjson want "$(bucket_want "${bucket}" "${sub}")" \
                    "def norm: ${norm}; (\$live[0] | norm) == (\$want | norm)" > /dev/null; then
                say "  ${bucket} ${sub}" 'in sync'
            else
                say "  ${bucket} ${sub}" 'UPDATE'; act "bucket-${sub}" "${bucket}"
            fi
        done
        policy="$(jq -r --arg n "${bucket}" '.buckets[] | select(.name == $n) | .policy' "${WORK}/estate.json")"
        if read_or_absent "${WORK}/live.json" s3api get-bucket-policy --bucket "${bucket}" \
                --expected-bucket-owner "${ACCOUNT}" --query Policy --output text \
            && same "${WORK}/live.json" "${WORK}/buckets/${policy}"; then
            say "  ${bucket} policy" 'in sync'
        else
            say "  ${bucket} policy" 'UPDATE'; act bucket-policy "${bucket}"
        fi
    done < <(jq -r '.buckets[].name' "${WORK}/estate.json")
}

declare -A SG_IDS=()
plan() {
    : > "${ACTIONS}"
    : > "${WORK}/versions"
    BLOCKED=''
    DB_SUBNET_GROUP=''
    DB_PARAMETER_GROUP=''
    plan_iam
    plan_profiles
    plan_estate
    plan_buckets
}

plan
#endregion --- [ Plan ] ---------------------------------------------------------------------- #

PENDING="$(wc -l < "${ACTIONS}")"
if ! ${APPLY} && ! ${EXPORT}; then
    [ -z "${BLOCKED}" ] || die "blocked: ${BLOCKED}; ${PENDING} other change(s) pending"
    if [ "${PENDING}" -eq 0 ]; then
        printf '\napply-dependencies: IN SYNC - live AWS matches dependencies/aws.\n'
        exit 0
    fi
    printf '\napply-dependencies: PLAN ONLY - %s change(s); nothing was written. Re-run with --apply.\n' "${PENDING}"
    exit 2
fi
# An export records live IAM as this tree's, so nothing may be pending. A blocked estate object is
# not IAM, and does not stop it.
if ! ${APPLY} && [ "${PENDING}" -gt 0 ]; then
    die "--export records live IAM, which differs from this tree: ${PENDING} change(s) pending; re-run with --apply"
fi

#region ------ [ Apply ] --------------------------------------------------------------------- #
apply_action() {
    local verb="$1" arn oldest sg_id description direction protocol ports peer permission rule_ids family value
    local -a rules
    shift
    case "${verb}" in
        policy-create)
            aws_ iam create-policy --policy-name "$1" --policy-document "file://${WORK}/policies/$1.json" > /dev/null ;;
        policy-version)
            arn="arn:aws:iam::${ACCOUNT}:policy/$1"
            # IAM keeps at most five versions; the oldest non-default one makes room.
            aws_ iam list-policy-versions --policy-arn "${arn}" --output json > "${WORK}/versions.json"
            if [ "$(jq '.Versions | length' "${WORK}/versions.json")" -ge 5 ]; then
                oldest="$(jq -r '[.Versions[] | select(.IsDefaultVersion | not)] | sort_by(.CreateDate)[0].VersionId' \
                          "${WORK}/versions.json")"
                aws_ iam delete-policy-version --policy-arn "${arn}" --version-id "${oldest}"
            fi
            aws_ iam create-policy-version --policy-arn "${arn}" --set-as-default \
                --policy-document "file://${WORK}/policies/$1.json" > /dev/null ;;
        role-create)
            aws_ iam create-role --role-name "$1" --max-session-duration "$2" \
                --assume-role-policy-document "file://${WORK}/roles/$1.trust.json" > /dev/null ;;
        role-trust)
            aws_ iam update-assume-role-policy --role-name "$1" --policy-document "file://${WORK}/roles/$1.trust.json" ;;
        role-session)
            aws_ iam update-role --role-name "$1" --max-session-duration "$2" ;;
        role-boundary-delete)
            aws_ iam delete-role-permissions-boundary --role-name "$1" ;;
        role-inline-delete)
            aws_ iam delete-role-policy --role-name "$1" --policy-name "$2" ;;
        role-detach)
            aws_ iam detach-role-policy --role-name "$1" --policy-arn "$2" ;;
        role-attach)
            aws_ iam attach-role-policy --role-name "$1" --policy-arn "$2" ;;
        slr-create)
            aws_ iam create-service-linked-role --aws-service-name "$1" > /dev/null ;;
        subnetgroup-create)
            description="$(jq -r --arg n "$1" '.db_subnet_groups[] | select(.name == $n) | .description' "${WORK}/estate.json")"
            aws_ rds create-db-subnet-group --db-subnet-group-name "$1" --db-subnet-group-description "${description}" \
                --subnet-ids "${SUBNETS[@]}" --tags "${ESTATE_TAGS_JSON}" > /dev/null ;;
        subnetgroup-modify)
            aws_ rds modify-db-subnet-group --db-subnet-group-name "$1" --subnet-ids "${SUBNETS[@]}" > /dev/null ;;
        pg-create)
            description="$(jq -r --arg n "$1" '.db_parameter_groups[] | select(.name == $n) | .description' "${WORK}/estate.json")"
            family="$(jq -r --arg n "$1" '.db_parameter_groups[] | select(.name == $n) | .family' "${WORK}/estate.json")"
            aws_ rds create-db-parameter-group --db-parameter-group-name "$1" --db-parameter-group-family "${family}" \
                --description "${description}" --tags "${ESTATE_TAGS_JSON}" > /dev/null ;;
        pg-modify)
            # Static parameters such as shared_buffers take effect only at a reboot, so every write is
            # pending-reboot: a database boots with the group's values, which change only between runs.
            value="$(jq -r --arg n "$1" --arg p "$2" '.db_parameter_groups[] | select(.name == $n) | .parameters[$p]' "${WORK}/estate.json")"
            aws_ rds modify-db-parameter-group --db-parameter-group-name "$1" --parameters \
                "$(jq -cn --arg p "$2" --arg v "${value}" '[{ParameterName: $p, ParameterValue: $v, ApplyMethod: "pending-reboot"}]')" > /dev/null ;;
        pg-reset)
            # Without --no-reset-all-parameters RDS resets every parameter in the group, and applies
            # the dynamic ones at once.
            aws_ rds reset-db-parameter-group --db-parameter-group-name "$1" --no-reset-all-parameters --parameters \
                "$(jq -cn --arg p "$2" '[{ParameterName: $p, ApplyMethod: "pending-reboot"}]')" > /dev/null ;;
        sg-create)
            description="$(jq -r --arg n "$1" '.security_groups[] | select(.name == $n) | .description' "${WORK}/estate.json")"
            sg_id="$(aws_ ec2 create-security-group --group-name "$1" --description "${description}" --vpc-id "${VPC}" \
                     --tag-specifications "$(jq -cn --argjson t "${ESTATE_TAGS_JSON}" '[{ResourceType: "security-group", Tags: $t}]')" \
                     --query GroupId --output text)"
            SG_IDS["$1"]="${sg_id}"
            # A new group allows all egress, over IPv6 too when the VPC has an IPv6 range. The
            # declaration is the whole truth, so every egress rule the group was born with goes.
            rule_ids="$(aws_ ec2 describe-security-group-rules --filters "Name=group-id,Values=${sg_id}" \
                        --query 'SecurityGroupRules[?IsEgress].SecurityGroupRuleId' --output text)"
            read -r -a rules <<< "${rule_ids}"
            aws_ ec2 revoke-security-group-egress --group-id "${sg_id}" --security-group-rule-ids "${rules[@]}" > /dev/null ;;
        sg-authorize)
            read -r direction protocol ports peer <<< "$2"
            description="$(jq -r --arg n "$1" --arg d "${direction}" --arg pr "${protocol}" --arg p "${ports%-*}" \
                --arg peer "${peer#sg:}" '.security_groups[] | select(.name == $n) | .[$d][]
                  | select(.protocol == $pr and (.port | tostring) == $p and .source == $peer) | .description' \
                "${WORK}/estate.json")"
            permission="$(jq -cn --arg pr "${protocol}" --argjson f "${ports%-*}" --argjson t "${ports#*-}" \
                --arg g "${SG_IDS[${peer#sg:}]}" --arg d "${description}" \
                '[{IpProtocol: $pr, FromPort: $f, ToPort: $t, UserIdGroupPairs: [{GroupId: $g, Description: $d}]}]')"
            aws_ ec2 "authorize-security-group-${direction}" --group-id "${SG_IDS[$1]}" \
                --ip-permissions "${permission}" > /dev/null ;;
        sg-revoke)
            # By rule id, which revokes a rule of any peer kind: address, group, prefix list or IPv6.
            aws_ ec2 "revoke-security-group-$2" --group-id "${SG_IDS[$1]}" --security-group-rule-ids "$3" > /dev/null ;;
        profile-create)
            aws_ iam create-instance-profile --instance-profile-name "$1" > /dev/null ;;
        profile-remove-role)
            aws_ iam remove-role-from-instance-profile --instance-profile-name "$1" --role-name "$2" ;;
        profile-add-role)
            aws_ iam add-role-to-instance-profile --instance-profile-name "$1" --role-name "$2" ;;
        bucket-create)
            # Tagged in the create itself, so no bucket of this tree's ever exists untagged.
            # us-east-1 takes no LocationConstraint; any other REGION must pass one.
            aws_ s3api create-bucket --bucket "$1" --object-ownership \
                "$(jq -r --arg n "$1" '.buckets[] | select(.name == $n) | .object_ownership' "${WORK}/estate.json")" \
                --create-bucket-configuration "$(jq -cn --argjson t "${ESTATE_TAGS_JSON}" '{Tags: $t}')" > /dev/null ;;
        bucket-tags)
            aws_ s3api put-bucket-tagging --bucket "$1" --expected-bucket-owner "${ACCOUNT}" --tagging "$(bucket_want "$1" tags)" ;;
        bucket-public-access-block)
            aws_ s3api put-public-access-block --bucket "$1" --expected-bucket-owner "${ACCOUNT}" \
                --public-access-block-configuration "$(bucket_want "$1" public-access-block)" ;;
        bucket-ownership)
            aws_ s3api put-bucket-ownership-controls --bucket "$1" --expected-bucket-owner "${ACCOUNT}" \
                --ownership-controls "$(bucket_want "$1" ownership)" ;;
        bucket-encryption)
            aws_ s3api put-bucket-encryption --bucket "$1" --expected-bucket-owner "${ACCOUNT}" \
                --server-side-encryption-configuration "$(bucket_want "$1" encryption)" ;;
        bucket-lifecycle)
            aws_ s3api put-bucket-lifecycle-configuration --bucket "$1" --expected-bucket-owner "${ACCOUNT}" \
                --lifecycle-configuration "$(bucket_want "$1" lifecycle)" > /dev/null ;;
        bucket-policy)
            aws_ s3api put-bucket-policy --bucket "$1" --expected-bucket-owner "${ACCOUNT}" --policy \
                "file://${WORK}/buckets/$(jq -r --arg n "$1" '.buckets[] | select(.name == $n) | .policy' "${WORK}/estate.json")" ;;
    esac
    say "${verb}" "$* done"
}

if [ "${PENDING}" -gt 0 ]; then
    echo '== apply =='
    cp "${ACTIONS}" "${WORK}/applying"
    # Each step's dependencies are written first. Detach precedes attach: a role at its policy
    # quota can take a declared policy only after an undeclared one is gone, and a profile holds
    # one role. New versions of existing policies go last, so a widened grant, such as passing the
    # instance role, lands only once everything it reaches exists and is configured.
    for verb in slr-create policy-create role-create role-trust role-session role-boundary-delete \
                role-inline-delete role-detach role-attach profile-create profile-remove-role profile-add-role \
                subnetgroup-create subnetgroup-modify pg-create pg-modify pg-reset sg-create sg-authorize sg-revoke \
                bucket-create bucket-tags bucket-public-access-block bucket-ownership bucket-encryption \
                bucket-lifecycle bucket-policy policy-version; do
        while read -r action_verb target rest; do
            [ "${action_verb}" = "${verb}" ] || continue
            # A rule key is one argument with spaces; every other action's fields are words.
            case "${verb}" in
                sg-authorize) apply_action "${verb}" "${target}" "${rest}" ;;
                *) read -r -a fields <<< "${rest}"; apply_action "${verb}" "${target}" "${fields[@]}" ;;
            esac
        done < "${WORK}/applying"
    done

    echo '== verify: re-plan after apply =='
    plan
    [ ! -s "${ACTIONS}" ] || die "live AWS still differs after apply: $(tr '\n' ';' < "${ACTIONS}")"
fi
#endregion --- [ Apply ] --------------------------------------------------------------------- #

#region ------ [ Verify ] -------------------------------------------------------------------- #
# The guards are evidenced, not asserted: each role is simulated against requests its guards must
# allow and deny. A decision other than the expected one fails the run.
echo '== verify: simulate the roles =='
role_arn() { printf 'arn:aws:iam::%s:role/%s_%s_%s' "${ACCOUNT}" "${OWNER}" "${REPO}" "$1"; }
HOST_ROLE="arn:aws:iam::${ACCOUNT}:role/nwarila-ec2-${REPO}-role"
principal() { # runner | reaper | admin | instance | a role ARN
    case "$1" in
        arn:*) printf '%s' "$1" ;;
        instance) printf '%s' "${HOST_ROLE}" ;;
        *) role_arn "$1" ;;
    esac
}
ctx() { printf 'ContextKeyName=%s,ContextKeyValues=%s,ContextKeyType=%s\n' "$1" "$2" "${3:-string}"; }
identity() { # aws:RequestTag | aws:ResourceTag
    ctx "$1/ManagedBy" Terraform
    ctx "$1/Repository" "${OWNER}/${REPO}"
    ctx "$1/RepositoryId" "${REPO_ID}"
    ctx "$1/CommitSha" 0
    ctx "$1/Environment" test
    ctx "$1/RunId" 0
}
# The declared database shape, with at most one condition replaced (key value type) or left out
# (key alone).
db_shape() {
    local key value type
    while read -r key value type; do
        if [ "${key}" != "${1:-}" ]; then ctx "${key}" "${value}" "${type}"
        elif [ "$#" -eq 3 ]; then ctx "$1" "$2" "$3"; fi
    done << 'EOF'
rds:DatabaseEngine postgres string
rds:DatabaseClass db.t4g.large string
rds:StorageSize 20 numeric
rds:StorageEncrypted true boolean
rds:ManageMasterUserPassword true boolean
rds:PubliclyAccessible false boolean
rds:MultiAz false boolean
EOF
}
expect() { # role expected-decision description action resource, then context entries on stdin
    local role="${1##*/}" want="$2" what="$3" action="$4" resource="$5" got
    local -a entries
    mapfile -t entries
    got="$(aws_ iam simulate-principal-policy --policy-source-arn "$(principal "$1")" --action-names "${action}" \
           --resource-arns "${resource}" --context-entries "${entries[@]}" \
           --query 'EvaluationResults[0].EvalDecision' --output text)"
    [ "${got}" = "${want}" ] || die "${role}: ${what}: expected ${want}, simulated ${got}"
    say "${role}: ${what}" "${got}"
}
DB="arn:aws:rds:${REGION}:${ACCOUNT}:db:gitlab"
PG="arn:aws:rds:${REGION}:${ACCOUNT}:pg:$(jq -r '.db_parameter_groups[0].name' "${WORK}/estate.json")"
DEFAULT_PG="arn:aws:rds:${REGION}:${ACCOUNT}:pg:default.$(jq -r '.db_parameter_groups[0].family' "${WORK}/estate.json")"
LB="arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT}:loadbalancer/net/gitlab/0"
ALB="arn:aws:elasticloadbalancing:${REGION}:${ACCOUNT}:loadbalancer/app/gitlab/0"
SECRET="arn:aws:secretsmanager:${REGION}:${ACCOUNT}:secret:rds!db-0"
REQ='aws:RequestTag'
RES='aws:ResourceTag'
NONE="$(ctx aws:RequestedRegion "${REGION}")"
OWN_SECRET="$(ctx aws:ResourceTag/aws:rds:primaryDBInstanceArn "${DB}")"

expect runner allowed      'create the declared database'   rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape)
# The provider names Multi-AZ only when it is on, so its absence is the single-AZ create.
expect runner allowed      'create without naming Multi-AZ' rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape rds:MultiAz)
expect runner implicitDeny 'create a multi-AZ database'     rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape rds:MultiAz true boolean)
expect runner implicitDeny 'create another engine'         rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape rds:DatabaseEngine mysql string)
expect runner implicitDeny 'create a smaller class'         rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape rds:DatabaseClass db.t4g.medium string)
expect runner implicitDeny 'create a larger class'          rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape rds:DatabaseClass db.r6g.large string)
expect runner implicitDeny 'create unencrypted storage'     rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape rds:StorageEncrypted false boolean)
expect runner implicitDeny 'create more storage'            rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape rds:StorageSize 21 numeric)
expect runner implicitDeny 'create a public database'       rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape rds:PubliclyAccessible true boolean)
expect runner implicitDeny 'create with a typed password'   rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape rds:ManageMasterUserPassword false boolean)
expect runner implicitDeny 'create without the identity'    rds:CreateDBInstance "${DB}" < <(db_shape)
# A create authorizes each group it references as a resource of its own.
expect runner allowed      'create with the tuned group'    rds:CreateDBInstance "${PG}" < <(identity "${REQ}"; db_shape)
expect runner implicitDeny 'create with the default group'  rds:CreateDBInstance "${DEFAULT_PG}" < <(identity "${REQ}"; db_shape)
for action in rds:CreateDBParameterGroup rds:ModifyDBParameterGroup rds:DeleteDBParameterGroup; do
    expect runner implicitDeny "${action#rds:} on the group" "${action}" "${PG}" <<< "${NONE}"
done
expect runner allowed      'delete the owned database'      rds:DeleteDBInstance "${DB}" < <(identity "${RES}")
expect runner implicitDeny 'delete an unowned database'     rds:DeleteDBInstance "${DB}" <<< "${NONE}"
# Keycloak's database is offered with this repository's tags, so only the resource can deny it.
for action in rds:DescribeDBLogFiles rds:DownloadDBLogFilePortion; do
    expect runner allowed      "${action#rds:} on the owned database"   "${action}" "${DB}" < <(identity "${RES}")
    expect runner implicitDeny "${action#rds:} on an unowned database"  "${action}" "${DB}" <<< "${NONE}"
    expect runner implicitDeny "${action#rds:} on keycloak's database"  "${action}" "${DB%:gitlab}:keycloak" < <(identity "${RES}")
done
expect runner allowed      'create the secret through RDS'  secretsmanager:CreateSecret "${SECRET}" < <(ctx aws:CalledVia rds.amazonaws.com stringList)
expect runner implicitDeny 'create a secret directly'       secretsmanager:CreateSecret "${SECRET}" <<< "${NONE}"
expect runner allowed      "read this database's secret"    secretsmanager:GetSecretValue "${SECRET}" <<< "${OWN_SECRET}"
expect runner implicitDeny "read another database's secret" secretsmanager:GetSecretValue "${SECRET}" \
    < <(ctx aws:ResourceTag/aws:rds:primaryDBInstanceArn "${DB}-other")
INSTANCE="arn:aws:ec2:${REGION}:${ACCOUNT}:instance/*"
expect runner allowed      'launch a t3.large'              ec2:RunInstances "${INSTANCE}" < <(identity "${REQ}"; ctx ec2:InstanceType t3.large)
expect runner allowed      'launch a t3.medium'             ec2:RunInstances "${INSTANCE}" < <(identity "${REQ}"; ctx ec2:InstanceType t3.medium)
expect runner allowed      'launch a t3.small'              ec2:RunInstances "${INSTANCE}" < <(identity "${REQ}"; ctx ec2:InstanceType t3.small)
expect runner implicitDeny 'launch the next size up'        ec2:RunInstances "${INSTANCE}" < <(identity "${REQ}"; ctx ec2:InstanceType t3.xlarge)
expect runner implicitDeny 'launch a larger size'           ec2:RunInstances "${INSTANCE}" < <(identity "${REQ}"; ctx ec2:InstanceType m5.24xlarge)
expect runner allowed      'create the internal balancer'   elasticloadbalancing:CreateLoadBalancer "${LB}" \
    < <(identity "${REQ}"; ctx elasticloadbalancing:Scheme internal)
expect runner implicitDeny 'create a public balancer'       elasticloadbalancing:CreateLoadBalancer "${LB}" \
    < <(identity "${REQ}"; ctx elasticloadbalancing:Scheme internet-facing)
expect runner implicitDeny 'create an application load balancer named gitlab' \
    elasticloadbalancing:CreateLoadBalancer "${ALB}" < <(identity "${REQ}"; ctx elasticloadbalancing:Scheme internal)
expect runner implicitDeny 'tag a balancer after creation'  elasticloadbalancing:AddTags "${LB}" <<< "${NONE}"
# The provider sets a network balancer's security groups inside its create, once it exists.
expect runner allowed      "set an owned balancer's groups" elasticloadbalancing:SetSecurityGroups "${LB}" < <(identity "${RES}")
expect runner implicitDeny "set an unowned balancer's groups" \
    elasticloadbalancing:SetSecurityGroups "${LB}" <<< "${NONE}"
expect runner allowed      'delete the owned balancer'      elasticloadbalancing:DeleteLoadBalancer "${LB}" < <(identity "${RES}")
expect runner implicitDeny 'delete an unowned balancer'     elasticloadbalancing:DeleteLoadBalancer "${LB}" <<< "${NONE}"
expect runner implicitDeny 'attach a policy (escalation)'   iam:AttachRolePolicy "$(role_arn runner)" <<< "${NONE}"
expect reaper allowed      'delete the owned database'      rds:DeleteDBInstance "${DB}" < <(identity "${RES}")
expect reaper implicitDeny 'create a database'              rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape)
expect reaper implicitDeny 'delete the parameter group'     rds:DeleteDBParameterGroup "${PG}" <<< "${NONE}"
expect reaper allowed      'delete the owned balancer'      elasticloadbalancing:DeleteLoadBalancer "${LB}" < <(identity "${RES}")
expect reaper implicitDeny 'delete an unowned balancer'     elasticloadbalancing:DeleteLoadBalancer "${LB}" <<< "${NONE}"
expect admin  allowed      "read this database's secret"    secretsmanager:GetSecretValue "${SECRET}" <<< "${OWN_SECRET}"
expect admin  implicitDeny 'create a database'              rds:CreateDBInstance "${DB}" < <(identity "${REQ}"; db_shape)

HOST_PROFILE="arn:aws:iam::${ACCOUNT}:instance-profile/nwarila-ec2-${REPO}-profile"
OBJECTS="arn:aws:s3:::$(jq -r '.buckets[0].name' "${WORK}/estate.json")"
RUN_OBJECT="${OBJECTS}/runs/0/x"
TO_EC2="$(ctx iam:PassedToService ec2.amazonaws.com)"
OWN="$(ctx aws:ResourceAccount "${ACCOUNT}")"
expect runner allowed      'pass the instance role to EC2'     iam:PassRole "${HOST_ROLE}" <<< "${TO_EC2}"
expect runner implicitDeny 'pass the instance role to Lambda'  iam:PassRole "${HOST_ROLE}" < <(ctx iam:PassedToService lambda.amazonaws.com)
expect runner implicitDeny 'pass another EC2 role'             iam:PassRole "arn:aws:iam::${ACCOUNT}:role/nwarila-ec2-other-role" \
    <<< "${TO_EC2}"
expect runner allowed      'read the instance profile'         iam:GetInstanceProfile "${HOST_PROFILE}" <<< "${NONE}"
expect runner implicitDeny 'write a run object'                s3:PutObject "${RUN_OBJECT}" <<< "${OWN}"
expect runner implicitDeny 'read a run object'                 s3:GetObject "${RUN_OBJECT}" <<< "${OWN}"
expect runner implicitDeny "replace the bucket's policy"       s3:PutBucketPolicy "${OBJECTS}" <<< "${OWN}"
expect reaper allowed      'read the instance profile'         iam:GetInstanceProfile "${HOST_PROFILE}" <<< "${NONE}"
expect reaper implicitDeny 'pass the instance role to EC2'     iam:PassRole "${HOST_ROLE}" <<< "${TO_EC2}"
expect reaper implicitDeny 'read a run object'                 s3:GetObject "${RUN_OBJECT}" <<< "${OWN}"
# The admin role carries runner_iam, so it may launch a host with the instance role too.
expect admin  allowed      'pass the instance role to EC2'     iam:PassRole "${HOST_ROLE}" <<< "${TO_EC2}"
for action in s3:GetObject s3:PutObject s3:DeleteObject; do
    expect admin allowed "${action#s3:} a run object" "${action}" "${RUN_OBJECT}" <<< "${OWN}"
done
expect admin  allowed      'list under runs/'                  s3:ListBucket "${OBJECTS}" < <(echo "${OWN}"; ctx s3:prefix runs/0/)
expect admin  implicitDeny 'list the whole bucket'             s3:ListBucket "${OBJECTS}" <<< "${OWN}"
expect admin  implicitDeny 'write outside runs/'               s3:PutObject "${OBJECTS}/other/x" <<< "${OWN}"
expect admin  implicitDeny 'write a direct-upload temporary'   s3:PutObject "${OBJECTS}/tmp/uploads/x" <<< "${OWN}"
for action in s3:PutBucketPolicy s3:PutLifecycleConfiguration s3:DeleteBucket; do
    expect admin implicitDeny "${action#s3:} on the bucket" "${action}" "${OBJECTS}" <<< "${OWN}"
done
# The instance role reaches object data under runs/ and GitLab's direct-upload temporaries under
# tmp/uploads/ in this account's bucket, and SSM; nothing else.
for action in s3:GetObject s3:PutObject s3:DeleteObject s3:AbortMultipartUpload s3:ListMultipartUploadParts; do
    expect instance allowed "${action#s3:} a run object" "${action}" "${RUN_OBJECT}" <<< "${OWN}"
    expect instance allowed "${action#s3:} a direct-upload temporary" "${action}" "${OBJECTS}/tmp/uploads/x" <<< "${OWN}"
done
expect instance allowed      'list under runs/'                s3:ListBucket "${OBJECTS}" < <(echo "${OWN}"; ctx s3:prefix runs/0/)
expect instance allowed      'register with SSM'               ssm:UpdateInstanceInformation '*' <<< "${NONE}"
expect instance implicitDeny 'list the whole bucket'           s3:ListBucket "${OBJECTS}" <<< "${OWN}"
expect instance implicitDeny 'list outside runs/'              s3:ListBucket "${OBJECTS}" < <(echo "${OWN}"; ctx s3:prefix other/)
expect instance implicitDeny 'write outside runs/'             s3:PutObject "${OBJECTS}/other/x" <<< "${OWN}"
expect instance implicitDeny 'write elsewhere under tmp/'      s3:PutObject "${OBJECTS}/tmp/other" <<< "${OWN}"
expect instance implicitDeny "write another account's bucket"  s3:PutObject "${RUN_OBJECT}" < <(ctx aws:ResourceAccount 999999999999)
for bucket in apprepo ansible terraform; do
    expect instance implicitDeny "read the ${bucket} bucket" s3:GetObject "arn:aws:s3:::${ACCOUNT}-${bucket}/x" <<< "${OWN}"
done
expect instance implicitDeny 'write the apprepo bucket'        s3:PutObject "arn:aws:s3:::${ACCOUNT}-apprepo/x" <<< "${OWN}"
for action in s3:PutBucketPolicy s3:PutLifecycleConfiguration s3:PutBucketPublicAccessBlock s3:DeleteBucket; do
    expect instance implicitDeny "${action#s3:} on the bucket" "${action}" "${OBJECTS}" <<< "${OWN}"
done
expect instance implicitDeny 'pass a role'                     iam:PassRole "${HOST_ROLE}" <<< "${TO_EC2}"

# Every other repository's deploy and operator role is outside the instance role and the bucket.
aws_ iam list-roles --query 'Roles[].RoleName' --output json > "${WORK}/role-names.json"
mapfile -t OTHERS < <(jq -r --arg org "${OWNER}_" --arg own "${OWNER}_${REPO}_" \
    '.[] | select(startswith($org) and (startswith($own) | not) and test("_(runner|admin)$"))' "${WORK}/role-names.json")
[ "${#OTHERS[@]}" -gt 0 ] || die "found no other repository's runner or admin role to simulate"
for name in "${OTHERS[@]}"; do
    expect "arn:aws:iam::${ACCOUNT}:role/${name}" implicitDeny 'pass the GitLab instance role' iam:PassRole "${HOST_ROLE}" \
        <<< "${TO_EC2}"
    expect "arn:aws:iam::${ACCOUNT}:role/${name}" implicitDeny 'write a GitLab run object' s3:PutObject "${RUN_OBJECT}" \
        <<< "${OWN}"
done

# The bucket policy, for a caller whose own policy allows the request: it denies all but the two
# roles, and those too without TLS. The caller is the role under test, also given as the
# aws:PrincipalArn the policy's condition reads.
BUCKET_POLICY="${WORK}/buckets/$(jq -r '.buckets[0].policy' "${WORK}/estate.json")"
bucket_expect() { # expected-decision description principal-arn secure-transport action resource, then context on stdin
    local got
    local -a entries
    mapfile -t entries
    # --policy-input-list takes a JSON list: the CLI splits a bare document on its commas.
    jq -n --arg a "$5" --arg r "$6" '[{Version: "2012-10-17", Statement: [{Effect: "Allow", Action: $a, Resource: $r}]} | tojson]' \
        > "${WORK}/may.json"
    got="$(aws_ iam simulate-custom-policy --policy-input-list "file://${WORK}/may.json" \
           --resource-policy "file://${BUCKET_POLICY}" --caller-arn "$3" --action-names "$5" --resource-arns "$6" \
           --context-entries "$(ctx aws:PrincipalArn "$3")" "$(ctx aws:SecureTransport "$4" boolean)" "${entries[@]}" \
           --query 'EvaluationResults[0].EvalDecision' --output text)"
    [ "${got}" = "$1" ] || die "bucket policy: $2: expected $1, simulated ${got}"
    say "bucket policy: $2" "${got}"
}
RUNS="$(ctx s3:prefix runs/0/)"
bucket_expect allowed      'the instance role writes over TLS'  "${HOST_ROLE}" true s3:PutObject "${RUN_OBJECT}" < /dev/null
bucket_expect allowed      'the admin role writes over TLS'     "$(role_arn admin)" true s3:PutObject "${RUN_OBJECT}" < /dev/null
bucket_expect allowed      'the instance role lists runs/'      "${HOST_ROLE}" true s3:ListBucket "${OBJECTS}" <<< "${RUNS}"
bucket_expect allowed      'the admin role lists runs/'         "$(role_arn admin)" true s3:ListBucket "${OBJECTS}" <<< "${RUNS}"
bucket_expect explicitDeny 'the instance role without TLS'      "${HOST_ROLE}" false s3:PutObject "${RUN_OBJECT}" < /dev/null
for name in "${OTHERS[@]}"; do
    other="arn:aws:iam::${ACCOUNT}:role/${name}"
    bucket_expect explicitDeny "${name} writes"                  "${other}" true s3:PutObject "${RUN_OBJECT}" < /dev/null
    bucket_expect explicitDeny "${name} reads the null version"  "${other}" true s3:GetObjectVersion "${RUN_OBJECT}" < /dev/null
    bucket_expect explicitDeny "${name} lists runs/"             "${other}" true s3:ListBucket "${OBJECTS}" <<< "${RUNS}"
done
# This script runs as an account administrator, whom the deny does not except; another repository's
# role stands in for it. Configuring and inspecting the bucket stay open to it.
for action in s3:GetBucketLocation s3:GetBucketPolicy s3:GetBucketTagging s3:GetLifecycleConfiguration \
              s3:GetEncryptionConfiguration s3:GetBucketPublicAccessBlock s3:GetBucketOwnershipControls \
              s3:GetBucketVersioning s3:PutBucketPolicy; do
    bucket_expect allowed "${OTHERS[0]} ${action#s3:}" "arn:aws:iam::${ACCOUNT}:role/${OTHERS[0]}" true \
        "${action}" "${OBJECTS}" < /dev/null
done
#endregion --- [ Verify ] -------------------------------------------------------------------- #

#region ------ [ Export ] -------------------------------------------------------------------- #
EXPORT_NOTE='Exported from live IAM by scripts/apply-dependencies.sh --export on the date in exported, once nothing'
EXPORT_NOTE+=' was pending: every attached version is the live default version of a document this tree matched. A'
EXPORT_NOTE+=' document changed since is listed in not_yet_applied, with a null version while it does not exist yet,'
EXPORT_NOTE+=' until the next export.'
EXPORTED=''
if ${EXPORT}; then
    echo '== export: live IAM into dependencies/aws/manifest.json =='
    jq -R -n '[inputs | split("\t") | {(.[0]): .[1]}] | add' "${WORK}/versions" > "${WORK}/versions.json"
    jq --arg date "$(date -u +%F)" --slurpfile versions "${WORK}/versions.json" --arg note "${EXPORT_NOTE}" '
        .exported = $date
        | .roles[].attached[] |= (if .managed_by == "aws" then . else .version = $versions[0][.name] end)
        | .divergence = {note: $note, not_yet_applied: []}' "${DEP}/manifest.json" > "${WORK}/manifest.json"
    mv "${WORK}/manifest.json" "${DEP}/manifest.json"
    # The command dependencies/README.md gives, so the bundle digest is reproducible.
    # shellcheck disable=SC2094 # find excludes MANIFEST.sha256; the pipeline only writes it
    (cd "${ROOT}/dependencies" && LC_ALL=C find . -type f ! -name MANIFEST.sha256 -print0 | LC_ALL=C sort -z \
        | xargs -0 sha256sum > MANIFEST.sha256)
    python3 "${ROOT}/scripts/check-dependencies.py" > /dev/null || die 'the exported manifest fails scripts/check-dependencies.py'
    say 'dependencies/aws/manifest.json' "exported $(jq -r .exported "${DEP}/manifest.json"); commit it with MANIFEST.sha256"
    EXPORTED='; manifest exported'
fi
#endregion --- [ Export ] -------------------------------------------------------------------- #

echo '== names and ids the deployment consumes =='
while read -r profile; do
    say 'iam_instance_profile for the Rails nodes' "${profile}"
done < <(jq -r '.instance_profiles | keys[]' "${DEP}/manifest.json")
while read -r bucket; do
    say 'objects bucket' "${bucket}"
done < <(jq -r '.buckets[].name' "${WORK}/estate.json")
[ -z "${DB_SUBNET_GROUP}" ] || say 'db_subnet_group_name' "${DB_SUBNET_GROUP}"
[ -z "${DB_PARAMETER_GROUP}" ] || say 'parameter_group_name' "${DB_PARAMETER_GROUP}"
mapfile -t SG_NAMES < <(printf '%s\n' "${!SG_IDS[@]}" | sort)
for sg_name in "${SG_NAMES[@]}"; do
    say "security group ${sg_name}" "${SG_IDS[${sg_name}]}"
done
if [ -n "${BLOCKED}" ]; then
    [ "${PENDING}" -eq 0 ] \
        || die "applied everything else; still blocked: ${BLOCKED}; ${PENDING} change(s) applied and verified${EXPORTED}"
    die "still blocked: ${BLOCKED}; 0 change(s) applied and verified${EXPORTED}"
fi
if [ "${PENDING}" -eq 0 ]; then
    printf '\napply-dependencies: IN SYNC and verified - nothing needed writing.\n'
elif ${EXPORT}; then
    printf '\napply-dependencies: APPLIED, verified and exported.\n'
else
    printf '\napply-dependencies: APPLIED and verified. Record live IAM with --export.\n'
fi
