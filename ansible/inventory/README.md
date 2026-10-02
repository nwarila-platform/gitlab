# ansible/inventory/

## There is no static inventory, and that is deliberate

The AWS deploy is **ephemeral**: every run creates a new instance, converges it, and destroys it.
An instance id written into a file here would be wrong the moment the run that produced it ended.

## `aws_ec2.yml` — one run's instance, describing itself

The file is in two parts. The first is the only part that is about this repository: the region, the
four tag filters that select one run's instance — `RepositoryId`, `RunId` and `Repository` from the
workflow's own environment, and `Environment` from `ENVIRONMENT` or `test` — and the `gitlab_servers`
group the play addresses. Everything below that is carried from the fleet's reference repository,
with two differences a STIG-hardened RHEL host needs (see below).

Hosts are named by their **Name tag**, which is the hostname Terraform declares, so
`inventory_hostname` is the system's own name and nothing downstream has to be told it again. Every
attribute the plugin publishes is namespaced with `aws_`, which keeps the EC2 instance `state` from
colliding with the role input that selects `present_redhat.yml` or `absent_redhat.yml`.

## Everything else is derived from the instance

| Value | Derived from |
|---|---|
| Operating system, login account, shell type | `platform_details`, which every instance carries and which names the platform it is licensed as |
| Connection, port, address, SSM proxy | the `Connection` tag |
| `ENV` (the framework loader's input) | the `Environment` tag |

The private key is not the inventory's: the play's ordered credential sets name it, and
`credential_resolver` publishes the set that works as the host's identity. An
`ansible_ssh_private_key_file` set here would outrank that published identity, so the inventory sets
none.

The `Connection` tag takes four values, and absent means `ssh-direct`:

| Value | Reaches the host by |
|---|---|
| `ssh-direct` | SSH to the routable address on 22 |
| `ssh-ssm` | SSH to the instance id, tunnelled by an SSM `ProxyCommand`; needs no inbound rule |
| `winrm-direct` | WinRM over HTTPS to the routable address on 5986 |
| `winrm-ssm` | WinRM over HTTPS to a local port an SSM port-forwarding session already holds open |

A WinRM leg also needs a password, because WinRM has no key authentication; the SSH legs
authenticate with the key pair.

## Where this differs from the reference inventory, and why

| Setting | Reference | Here | Why |
|---|---|---|---|
| `ansible_python_interpreter` on RHEL | `/usr/libexec/platform-python` | `/usr/bin/python3.12` | RHEL 8's platform-python is 3.6, below ansible-core 2.21's floor. The framework's `redhat_rocky_8` bootstrap installs 3.12 over `raw` before any module runs, and `dnf`/`rpm` respawn under platform-python for their bindings (measured 2026-09-30). |
| `ansible_pipelining` | unset | `true` | fapolicyd on a STIG host denies an interpreter opening an untrusted script, which is what a module staged as a file is. Pipelining streams it over stdin instead. |

Both are ignored by Windows connections, so they can move back into the reference inventory
unchanged.

## Running the playbook by hand

Export `GITHUB_REPOSITORY_ID`, `GITHUB_RUN_ID` and `GITHUB_REPOSITORY` plus AWS credentials, then
point `-i` at `aws_ec2.yml` while the instance still exists. Set `ENVIRONMENT` if the deployment is
not the default `test`. The play asserts its ownership contract, so a run whose tags do not match
fails closed.
