# terraform/ — data only

This directory carries **no `.tf` files and never will**. The AWS resources are declared by the
pinned `nwarila-platform/aws-terraform-framework`; this repository contributes only the variable
input that shapes them.

- `aws.tfvars` — the system declaration consumed verbatim by the framework. It pins, for each of
  nine systems, the availability zone, subnet, instance type, AMI, key pair, instance profile,
  disk layout, the network interface and its rules, and declares the database and the load
  balancer. The OS instances are not swap-eligible (`refresh = false`) until the application
  declares persistent data volumes.
- The framework SHA is pinned in `.github/terraform-framework-pin`.

`.github/workflows/aws-deploy.yml` checks the framework out at that pin, runs Terraform from
inside it, and passes this file with `-var-file`. The deployment identity (`environment`,
`repository`, `repository_id`, `commit_sha`, `run_id`) is supplied separately with `-var`, the
highest-precedence source, so the tags that satisfy the deploy role's create-time IAM conditions
cannot be overridden from here.

## The stack

| System | Zone | Type | Profile | `Function` |
|---|---|---|---|---|
| `tcnaw-gitlab01` | us-east-1c | t3.large | `nwarila-ec2-gitlab-profile` | `gitlab-rails` |
| `tcnaw-gitlab02` | us-east-1a | t3.large | `nwarila-ec2-gitlab-profile` | `gitlab-rails` |
| `tcnaw-gitaly01` | us-east-1c | t3.medium | `nwarila-ec2-profile` | `gitlab-gitaly` |
| `tcnaw-gitaly02` | us-east-1a | t3.medium | `nwarila-ec2-profile` | `gitlab-gitaly` |
| `tcnaw-gitaly03` | us-east-1c | t3.medium | `nwarila-ec2-profile` | `gitlab-gitaly` |
| `tcnaw-praefect01` | us-east-1c | t3.small | `nwarila-ec2-profile` | `gitlab-praefect` |
| `tcnaw-praefect02` | us-east-1a | t3.small | `nwarila-ec2-profile` | `gitlab-praefect` |
| `tcnaw-praefect03` | us-east-1c | t3.small | `nwarila-ec2-profile` | `gitlab-praefect` |
| `tcnaw-redis01` | us-east-1c | t3.small | `nwarila-ec2-profile` | `gitlab-redis` |

The `Function` tag places each system in its inventory group, attaches the two Rails nodes to
the HTTP and SSH target groups and the three Praefect nodes to the Praefect one. Only the Rails
nodes carry GitLab's own instance profile, the one identity that may write objects; the others
carry the SSM-only organization profile.

Three Gitaly nodes behind three Praefect nodes are GitLab's minimal Gitaly Cluster: Praefect
replicates every repository to all three, and the Rails nodes reach the cluster only through
Praefect. The Gitaly and Praefect nodes are spread over the two Rails zones.

- **The database**: one RDS PostgreSQL 17 instance, `gitlab`, single-AZ, `db.t4g.large`, 20 GiB
  encrypted, not public, with an RDS-managed master password. It boots with the standing `gitlab`
  parameter group (`dependencies/aws/estate.yml`), which carries GitLab's required values and the
  STIG and CIS settings; naming it needs the framework's `parameter_group_name`, which the pinned
  framework passes through. The shape is exactly what `runner_rds` may create, and a create
  naming any other group is denied. GitLab and Praefect each have a database of their own on it,
  owned by a role of their own: `gitlabhq_production` by `gitlab`, `praefect_production` by
  `praefect`. The master user, `gitlab_admin`, is used from the two deploy nodes only, the first
  Rails and the first Praefect node. Every converge there connects as it to read that service's
  role, its database and the extensions, and to create whatever is absent; the proof also creates
  `rds_tools` with it and reads the settings and password types only it may read. Neither service
  connects as it. Backups are off and nothing is kept: every run's database is new.
- **The load balancer**: one internal network load balancer, `gitlab`, across both zones,
  cross-zone balancing on. Listener 80 forwards to the Rails nodes' port 80 (`rails-http`);
  listener 22 forwards to gitlab-sshd on their port 2222 (`rails-ssh`). Both keep client
  addresses and check `/-/readiness` on port 80, so a node whose GitLab is stopped leaves both
  together. Listener 2305 forwards to the Praefect nodes (`praefect`) with a TCP check, as the
  reference architecture's HAProxy checks Praefect, and keeps no client addresses.

No node is both a client and a target of one listener. A Rails node is a target of 80 and 22 and
a client of 2305. A Gitaly node calls GitLab's internal API on 80 and may call Praefect on 2305,
and the first one runs the proofs over 22 as well; it is a target of none. A Praefect node is a
target of 2305 and calls nothing through the load balancer. With client addresses preserved, a
node that reached itself through the balancer would be dropped, so 80 and 22 must never have
such a node; 2305 keeps no client addresses, so it cannot hairpin.

## Security groups

Peers are named by group, never by address. Every node carries `gitlab-node`, and the Rails and
Praefect nodes also carry `gitlab-db-client`, the only group the database admits; the load
balancer carries `gitlab-lb`. These four standing groups belong to `dependencies/aws/estate.yml`;
this file names them by the ids `scripts/apply-dependencies.sh --apply` created and printed:
`gitlab-node` sg-0d1ebea3cf83a5b08, `gitlab-db-client` sg-0e731bddd6958768e, `gitlab-db`
sg-097bdbe65e2dd0215 and `gitlab-lb` sg-078525e6572561825. A group recreated by that script gets
a new id, which must be copied here.

Each node's interface also gets its own run-scoped rules:

| Node | Ingress | Egress beyond 443/tcp and 1194/udp to anywhere |
|---|---|---|
| Rails | 80 and 2222 from `gitlab-lb` and from `gitlab-node` | 5432 to `gitlab-db`; 6379 to `gitlab-node`; 2305 to `gitlab-lb` |
| Gitaly | 8075 from `gitlab-node` | 80 and 2305 to `gitlab-lb`; 8075 to `gitlab-node`; on `tcnaw-gitaly01`, which runs the proofs, 22 to `gitlab-lb` |
| Praefect | 2305 from `gitlab-lb` | 5432 to `gitlab-db`; 8075 to `gitlab-node` |
| Redis | 6379 from `gitlab-node` | none |

A Rails node admits 80 and 2222 from `gitlab-node` as well as from `gitlab-lb` because, with
client addresses preserved, a forwarded request arrives from the client node. Whether the
`gitlab-lb` reference alone admits that traffic is unproven, so both are declared. A Praefect
node admits 2305 from `gitlab-lb` alone: with client addresses off on that listener, every caller
and every health check arrives from the load balancer. The Rails nodes do not reach Gitaly, so a
Gitaly node's 8075 serves only Praefect and its peers, which replicate from one another. A Gitaly
node's 2305 egress is the route GitLab's Gitaly Cluster firewall table requires of it; nothing in
this deployment exercises it yet.

On the host, nftables admits SSH, ICMP and each node's ingress ports from this table, and drops
every other new connection. Unlike keycloak's ruleset, the service ports carry no rate limit:
these groups already admit only the GitLab nodes and the load balancer, and a Rails node opens
its Praefect and Redis pools at boot in bursts a limit could drop. SSH keeps its limit of 25 new
connections a second.

## Reachability

Reachability is **direct SSH over a launch-time public IPv4**: the shared subnets'
MapPublicIpOnLaunch assigns the address (no Elastic IP, no NAT), and at runtime the framework
attaches the only administrative ingress: one security group scoped to the runner's validated
public IPv4. SSM (via each instance profile's `AmazonSSMManagedInstanceCore`) is the
administrator's backup connection, not the primary path. Whether `subnet-0dbb7770d19f253ad` in
us-east-1a assigns a public address at launch is unproven until the first run that places a node
there.
