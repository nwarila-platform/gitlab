# =========================================================================================== #
# File: 'terraform/aws.tfvars'
# --- [ Description ] ----------------------------------------------------------------------- #
#
# Variable input for the pinned aws-terraform-framework (SHA in .github/terraform-framework-pin).
# Plain tfvars — the workflow passes this file to terraform verbatim. This repository declares
# NO .tf files of its own: resources live in the pinned framework, configuration in the pinned
# ansible-framework plus this repository's roles.
#
# REACHABILITY — DIRECT SSH OVER A PUBLIC IPv4. The workflow discovers the runner's public IPv4
# and passes it as the framework's runtime-only runner_ip variable. When an operator hostname is
# configured it resolves that too and passes debug_ip, which adds RDP for a person working on the
# host. The framework attaches one security group carrying both to every interface. Each instance
# receives a public IPv4 at launch; no Elastic IP is involved. The account has no NAT and no VPC
# endpoints.
#
# The dependency worth knowing: MapPublicIpOnLaunch is an attribute of a shared subnet no
# repository owns. Direct SSH requires the instance's launch-time public address as well as the
# runner-scoped security group.
#
# readiness_gate is FALSE by design: the playbook owns the bounded direct-SSH readiness check.
# Every host is Linux; SSH lands on the AMI's ec2-user and the composed play's bootstrap takes it
# from there.
#
# =========================================================================================== #

# environment and the deployment identity (repository, repository_id, commit_sha, run_id) are
# deliberately NOT in this file: the workflow passes them as -var flags placed AFTER this file on
# the command line. Terraform resolves repeated command-line assignments in the order given, so it
# is that ordering, not the kind of flag, that keeps this file from renaming the deployment.

all_systems = [
  {
    region   = "us_east_1"
    hostname = "tcnaw-gitlab01"
    # The Rails nodes span two zones, so either zone can be lost. Every subnet here is in the
    # account's only VPC.
    availability_zone = "us-east-1c"
    subnet_id         = "subnet-03a855e712be7b399"
    # The framework CONSUMES key pairs and never creates them, so this names the standing
    # account key pair. user_data installs its public half by reading IMDS; the private half
    # lives only in the AWS_EC2_SSH_PRIVATE_KEY organization secret and the runner's
    # temporary directory.
    key_name = "nwarila-ec2-key"
    # GitLab's own profile for its Rails nodes (dependencies/aws/): SSM, plus object data under
    # runs/ in the GitLab objects bucket. The controller fetches the package, so the host reads
    # no application repository. The runner role only reads and passes the profile named here.
    iam_instance_profile = "nwarila-ec2-gitlab-profile"
    aws_kms_alias        = "aws/ebs"
    # CIS Red Hat Enterprise Linux 8 — the same hardened base the secure-wazuh Linux legs use.
    ami = "ami-0ca8a2e788e4c5869"
    # No standalone data volumes yet, so the OS instance is not swap-eligible; a future
    # persistent deployment declares its data volumes below and flips this to true.
    refresh = false
    # Rails and Sidekiq: GitLab's documented floor for a memory-constrained node is 8 GB.
    instance_type = "t3.large"
    # Direct SSH reaches the launch-time public IPv4 through the runner-scoped framework SG.
    connection_type = "ssh"
    readiness_user  = "ec2-user"

    readiness_gate             = false
    readiness_command          = null
    readiness_script_dir       = null
    readiness_private_key_path = null
    imds_hop_limit             = 1
    set_state                  = null

    # Function places the node in its inventory group; gitlab-rails also attaches it to both
    # load balancer target groups.
    tags = {
      Function = "gitlab-rails"
      Backup   = false
    }

    root_block_device = {
      iops        = null
      tags        = {}
      throughput  = null
      volume_type = "gp3"
      volume_size = "50"
    }

    # The CIS RHEL 8 AMI ships TWO devices: /dev/sda1 (root, handled by root_block_device, which
    # the framework forces encrypted) and a 40 GiB /dev/sdf the image defines and Terraform would
    # otherwise never see. Restating it here re-renders the mapping with encrypted = true, which
    # is the only declarative way to encrypt a device the AMI ships unencrypted. No collision
    # with ebs_block_devices: the framework assigns those suffixes starting at 'd'.
    ami_block_device_overrides = [
      {
        device_name = "/dev/sdf"
        iops        = "3000"
        throughput  = "125"
        volume_size = "40"
        volume_type = "gp3"
      }
    ]

    ebs_block_devices = []

    network_interfaces = [
      {
        description    = "tcnaw-gitlab01 CI firewall"
        interface_type = null
        private_ip     = null
        # Membership the load balancer and the database admit (dependencies/aws/estate.yml).
        security_groups = ["sg-REPLACE-gitlab-node", "sg-REPLACE-gitlab-db-client"]
        # Peers by group, never by address. The load balancer preserves client addresses, so a
        # request it forwards arrives from the client node, which carries gitlab-node; its health
        # checks arrive from the load balancer itself. Whether the gitlab-lb reference alone also
        # admits the preserved traffic is unproven, so both are declared. The Rails nodes never
        # call the load balancer, so no node is both its client and its target.
        ingress = [
          {
            description                  = "HTTP health checks from the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 80
            to_port                      = 80
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-lb"
          },
          {
            description                  = "HTTP from load balancer clients"
            ip_protocol                  = "tcp"
            from_port                    = 80
            to_port                      = 80
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-node"
          },
          {
            description                  = "gitlab-sshd from the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 2222
            to_port                      = 2222
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-lb"
          },
          {
            description                  = "gitlab-sshd from load balancer clients"
            ip_protocol                  = "tcp"
            from_port                    = 2222
            to_port                      = 2222
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-node"
          }
        ]
        egress = [
          {
            description                  = "HTTPS out"
            ip_protocol                  = "tcp"
            from_port                    = 443
            to_port                      = 443
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          },
          # The VPN tunnel that carries the host onto the private network. Scoped by port rather
          # than by address: the profile names its endpoint by DNS, and that address changes.
          {
            description                  = "OpenVPN tunnel out"
            ip_protocol                  = "udp"
            from_port                    = 1194
            to_port                      = 1194
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          },
          {
            description                  = "PostgreSQL to the database"
            ip_protocol                  = "tcp"
            from_port                    = 5432
            to_port                      = 5432
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-db"
          },
          {
            description                  = "Redis on the Redis node"
            ip_protocol                  = "tcp"
            from_port                    = 6379
            to_port                      = 6379
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-node"
          },
          {
            description                  = "Gitaly on the Gitaly node"
            ip_protocol                  = "tcp"
            from_port                    = 8075
            to_port                      = 8075
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-node"
          }
        ]
        tags = {}
      }
    ]

    # No Elastic IP: the subnet auto-assigns the launch-time public IPv4 used for direct SSH.
    associate_public_ip = false
  },
  {
    region   = "us_east_1"
    hostname = "tcnaw-gitlab02"
    # The second Rails zone.
    availability_zone = "us-east-1a"
    subnet_id         = "subnet-0dbb7770d19f253ad"
    # The framework CONSUMES key pairs and never creates them, so this names the standing
    # account key pair. user_data installs its public half by reading IMDS; the private half
    # lives only in the AWS_EC2_SSH_PRIVATE_KEY organization secret and the runner's
    # temporary directory.
    key_name = "nwarila-ec2-key"
    # GitLab's own profile for its Rails nodes (dependencies/aws/): SSM, plus object data under
    # runs/ in the GitLab objects bucket. The controller fetches the package, so the host reads
    # no application repository. The runner role only reads and passes the profile named here.
    iam_instance_profile = "nwarila-ec2-gitlab-profile"
    aws_kms_alias        = "aws/ebs"
    # CIS Red Hat Enterprise Linux 8 — the same hardened base the secure-wazuh Linux legs use.
    ami = "ami-0ca8a2e788e4c5869"
    # No standalone data volumes yet, so the OS instance is not swap-eligible; a future
    # persistent deployment declares its data volumes below and flips this to true.
    refresh = false
    # Rails and Sidekiq: GitLab's documented floor for a memory-constrained node is 8 GB.
    instance_type = "t3.large"
    # Direct SSH reaches the launch-time public IPv4 through the runner-scoped framework SG.
    connection_type = "ssh"
    readiness_user  = "ec2-user"

    readiness_gate             = false
    readiness_command          = null
    readiness_script_dir       = null
    readiness_private_key_path = null
    imds_hop_limit             = 1
    set_state                  = null

    # Function places the node in its inventory group; gitlab-rails also attaches it to both
    # load balancer target groups.
    tags = {
      Function = "gitlab-rails"
      Backup   = false
    }

    root_block_device = {
      iops        = null
      tags        = {}
      throughput  = null
      volume_type = "gp3"
      volume_size = "50"
    }

    # The CIS RHEL 8 AMI ships TWO devices: /dev/sda1 (root, handled by root_block_device, which
    # the framework forces encrypted) and a 40 GiB /dev/sdf the image defines and Terraform would
    # otherwise never see. Restating it here re-renders the mapping with encrypted = true, which
    # is the only declarative way to encrypt a device the AMI ships unencrypted. No collision
    # with ebs_block_devices: the framework assigns those suffixes starting at 'd'.
    ami_block_device_overrides = [
      {
        device_name = "/dev/sdf"
        iops        = "3000"
        throughput  = "125"
        volume_size = "40"
        volume_type = "gp3"
      }
    ]

    ebs_block_devices = []

    network_interfaces = [
      {
        description    = "tcnaw-gitlab02 CI firewall"
        interface_type = null
        private_ip     = null
        # Membership the load balancer and the database admit (dependencies/aws/estate.yml).
        security_groups = ["sg-REPLACE-gitlab-node", "sg-REPLACE-gitlab-db-client"]
        # Peers by group, never by address. The load balancer preserves client addresses, so a
        # request it forwards arrives from the client node, which carries gitlab-node; its health
        # checks arrive from the load balancer itself. Whether the gitlab-lb reference alone also
        # admits the preserved traffic is unproven, so both are declared. The Rails nodes never
        # call the load balancer, so no node is both its client and its target.
        ingress = [
          {
            description                  = "HTTP health checks from the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 80
            to_port                      = 80
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-lb"
          },
          {
            description                  = "HTTP from load balancer clients"
            ip_protocol                  = "tcp"
            from_port                    = 80
            to_port                      = 80
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-node"
          },
          {
            description                  = "gitlab-sshd from the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 2222
            to_port                      = 2222
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-lb"
          },
          {
            description                  = "gitlab-sshd from load balancer clients"
            ip_protocol                  = "tcp"
            from_port                    = 2222
            to_port                      = 2222
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-node"
          }
        ]
        egress = [
          {
            description                  = "HTTPS out"
            ip_protocol                  = "tcp"
            from_port                    = 443
            to_port                      = 443
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          },
          # The VPN tunnel that carries the host onto the private network. Scoped by port rather
          # than by address: the profile names its endpoint by DNS, and that address changes.
          {
            description                  = "OpenVPN tunnel out"
            ip_protocol                  = "udp"
            from_port                    = 1194
            to_port                      = 1194
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          },
          {
            description                  = "PostgreSQL to the database"
            ip_protocol                  = "tcp"
            from_port                    = 5432
            to_port                      = 5432
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-db"
          },
          {
            description                  = "Redis on the Redis node"
            ip_protocol                  = "tcp"
            from_port                    = 6379
            to_port                      = 6379
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-node"
          },
          {
            description                  = "Gitaly on the Gitaly node"
            ip_protocol                  = "tcp"
            from_port                    = 8075
            to_port                      = 8075
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-node"
          }
        ]
        tags = {}
      }
    ]

    # No Elastic IP: the subnet auto-assigns the launch-time public IPv4 used for direct SSH.
    associate_public_ip = false
  },
  {
    region   = "us_east_1"
    hostname = "tcnaw-gitaly01"
    # Beside the first Rails node.
    availability_zone = "us-east-1c"
    subnet_id         = "subnet-03a855e712be7b399"
    # The framework CONSUMES key pairs and never creates them, so this names the standing
    # account key pair. user_data installs its public half by reading IMDS; the private half
    # lives only in the AWS_EC2_SSH_PRIVATE_KEY organization secret and the runner's
    # temporary directory.
    key_name = "nwarila-ec2-key"
    # The org EC2 baseline: SSM only. This node never writes objects: only the Rails nodes do.
    iam_instance_profile = "nwarila-ec2-profile"
    aws_kms_alias        = "aws/ebs"
    # CIS Red Hat Enterprise Linux 8 — the same hardened base the secure-wazuh Linux legs use.
    ami = "ami-0ca8a2e788e4c5869"
    # No standalone data volumes yet, so the OS instance is not swap-eligible; a future
    # persistent deployment declares its data volumes below and flips this to true.
    refresh = false
    # Gitaly alone, at proof size.
    instance_type = "t3.medium"
    # Direct SSH reaches the launch-time public IPv4 through the runner-scoped framework SG.
    connection_type = "ssh"
    readiness_user  = "ec2-user"

    readiness_gate             = false
    readiness_command          = null
    readiness_script_dir       = null
    readiness_private_key_path = null
    imds_hop_limit             = 1
    set_state                  = null

    # Function places the node in its inventory group.
    tags = {
      Function = "gitlab-gitaly"
      Backup   = false
    }

    root_block_device = {
      iops        = null
      tags        = {}
      throughput  = null
      volume_type = "gp3"
      volume_size = "50"
    }

    # The CIS RHEL 8 AMI ships TWO devices: /dev/sda1 (root, handled by root_block_device, which
    # the framework forces encrypted) and a 40 GiB /dev/sdf the image defines and Terraform would
    # otherwise never see. Restating it here re-renders the mapping with encrypted = true, which
    # is the only declarative way to encrypt a device the AMI ships unencrypted. No collision
    # with ebs_block_devices: the framework assigns those suffixes starting at 'd'.
    ami_block_device_overrides = [
      {
        device_name = "/dev/sdf"
        iops        = "3000"
        throughput  = "125"
        volume_size = "40"
        volume_type = "gp3"
      }
    ]

    ebs_block_devices = []

    network_interfaces = [
      {
        description    = "tcnaw-gitaly01 CI firewall"
        interface_type = null
        private_ip     = null
        # Membership the load balancer admits (dependencies/aws/estate.yml).
        security_groups = ["sg-REPLACE-gitlab-node"]
        # Peers by group, never by address.
        ingress = [
          {
            description                  = "Gitaly from the Rails nodes"
            ip_protocol                  = "tcp"
            from_port                    = 8075
            to_port                      = 8075
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-node"
          }
        ]
        egress = [
          {
            description                  = "HTTPS out"
            ip_protocol                  = "tcp"
            from_port                    = 443
            to_port                      = 443
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          },
          # The VPN tunnel that carries the host onto the private network. Scoped by port rather
          # than by address: the profile names its endpoint by DNS, and that address changes.
          {
            description                  = "OpenVPN tunnel out"
            ip_protocol                  = "udp"
            from_port                    = 1194
            to_port                      = 1194
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          },
          # The internal API and the proofs reach the Rails nodes only through the load balancer.
          {
            description                  = "HTTP to the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 80
            to_port                      = 80
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-lb"
          },
          {
            description                  = "SSH to the load balancer"
            ip_protocol                  = "tcp"
            from_port                    = 22
            to_port                      = 22
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-lb"
          }
        ]
        tags = {}
      }
    ]

    # No Elastic IP: the subnet auto-assigns the launch-time public IPv4 used for direct SSH.
    associate_public_ip = false
  },
  {
    region   = "us_east_1"
    hostname = "tcnaw-redis01"
    # Beside the first Rails node.
    availability_zone = "us-east-1c"
    subnet_id         = "subnet-03a855e712be7b399"
    # The framework CONSUMES key pairs and never creates them, so this names the standing
    # account key pair. user_data installs its public half by reading IMDS; the private half
    # lives only in the AWS_EC2_SSH_PRIVATE_KEY organization secret and the runner's
    # temporary directory.
    key_name = "nwarila-ec2-key"
    # The org EC2 baseline: SSM only. This node never writes objects: only the Rails nodes do.
    iam_instance_profile = "nwarila-ec2-profile"
    aws_kms_alias        = "aws/ebs"
    # CIS Red Hat Enterprise Linux 8 — the same hardened base the secure-wazuh Linux legs use.
    ami = "ami-0ca8a2e788e4c5869"
    # No standalone data volumes yet, so the OS instance is not swap-eligible; a future
    # persistent deployment declares its data volumes below and flips this to true.
    refresh = false
    # Redis alone.
    instance_type = "t3.small"
    # Direct SSH reaches the launch-time public IPv4 through the runner-scoped framework SG.
    connection_type = "ssh"
    readiness_user  = "ec2-user"

    readiness_gate             = false
    readiness_command          = null
    readiness_script_dir       = null
    readiness_private_key_path = null
    imds_hop_limit             = 1
    set_state                  = null

    # Function places the node in its inventory group.
    tags = {
      Function = "gitlab-redis"
      Backup   = false
    }

    root_block_device = {
      iops        = null
      tags        = {}
      throughput  = null
      volume_type = "gp3"
      volume_size = "50"
    }

    # The CIS RHEL 8 AMI ships TWO devices: /dev/sda1 (root, handled by root_block_device, which
    # the framework forces encrypted) and a 40 GiB /dev/sdf the image defines and Terraform would
    # otherwise never see. Restating it here re-renders the mapping with encrypted = true, which
    # is the only declarative way to encrypt a device the AMI ships unencrypted. No collision
    # with ebs_block_devices: the framework assigns those suffixes starting at 'd'.
    ami_block_device_overrides = [
      {
        device_name = "/dev/sdf"
        iops        = "3000"
        throughput  = "125"
        volume_size = "40"
        volume_type = "gp3"
      }
    ]

    ebs_block_devices = []

    network_interfaces = [
      {
        description    = "tcnaw-redis01 CI firewall"
        interface_type = null
        private_ip     = null
        # Membership the GitLab peers share (dependencies/aws/estate.yml).
        security_groups = ["sg-REPLACE-gitlab-node"]
        # Peers by group, never by address.
        ingress = [
          {
            description                  = "Redis from the Rails nodes"
            ip_protocol                  = "tcp"
            from_port                    = 6379
            to_port                      = 6379
            cidr_ipv4                    = null
            prefix_list_id               = null
            referenced_security_group_id = "sg-REPLACE-gitlab-node"
          }
        ]
        egress = [
          {
            description                  = "HTTPS out"
            ip_protocol                  = "tcp"
            from_port                    = 443
            to_port                      = 443
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          },
          # The VPN tunnel that carries the host onto the private network. Scoped by port rather
          # than by address: the profile names its endpoint by DNS, and that address changes.
          {
            description                  = "OpenVPN tunnel out"
            ip_protocol                  = "udp"
            from_port                    = 1194
            to_port                      = 1194
            cidr_ipv4                    = "0.0.0.0/0"
            prefix_list_id               = null
            referenced_security_group_id = null
          }
        ]
        tags = {}
      }
    ]

    # No Elastic IP: the subnet auto-assigns the launch-time public IPv4 used for direct SSH.
    associate_public_ip = false
  }
]

# The database GitLab's Rails nodes share. Single-AZ: the cheapest database that proves the
# distributed shape. The shape is exactly what the runner may create
# (dependencies/aws/policies/nwarila-platform_gitlab_runner_rds.json): postgres, db.t4g.large,
# 20 GiB, no storage autoscaling, encrypted, not public, an RDS-managed password, and the
# standing 'gitlab' parameter group (dependencies/aws/estate.yml), which holds GitLab's required
# values; a create naming any other group is denied. ca_cert_identifier stays null: a non-default
# one makes the provider modify the instance after creating it, which the runner may not. The
# master user is used from the deploy node only. Every converge there connects as it to read
# GitLab's own role, its database and the extensions, and to create whatever is absent; the
# proof also creates rds_tools with it and reads the settings and password types only it may
# read. GitLab never connects as it.
all_databases = [
  {
    region                 = "us_east_1"
    availability_zone      = "us-east-1c"
    multi_az               = false
    db_name                = "gitlab"
    db_subnet_group_name   = "gitlab"
    vpc_security_group_ids = ["sg-REPLACE-gitlab-db"]
    engine                 = "postgres"
    # The major release is the pin: RDS creates the current minor of PostgreSQL 17, the only
    # major GitLab 19 supports.
    engine_version       = "17"
    instance_class       = "db.t4g.large"
    parameter_group_name = "gitlab"
    # Not "gitlab": that is the name of GitLab's own role, which this user creates.
    username                            = "gitlab_admin"
    manage_master_user_password         = true
    iam_database_authentication_enabled = false
    # Both keys are AWS managed and free. An AWS managed key works only through its own service,
    # so the master secret cannot share the storage key.
    aws_kms_alias                = "aws/rds"
    master_user_secret_kms_alias = "aws/secretsmanager"
    allocated_storage            = "20"
    max_allocated_storage        = "0"
    storage_type                 = "gp3"
    dedicated_log_volume         = false
    blue_green_update            = false
    ca_cert_identifier           = null
    # Ephemeral: nothing is kept after the run.
    backup_retention_period  = "0"
    backup_window            = null
    delete_automated_backups = true
    deletion_protection      = false
    skip_final_snapshot      = true

    tags = {
      Function = "gitlab-db"
      Backup   = false
    }
  }
]

# Internal by the framework's rule and the runner's: every client is inside the VPC. A network
# load balancer, because SSH, and later Praefect, are TCP. It spans both Rails zones with
# cross-zone balancing on, so either node serves either zone: 80 to the Rails nodes' NGINX, 22 to
# gitlab-sshd on 2222. Both target groups check /-/readiness on port 80, so a node whose GitLab
# is stopped leaves both together, and both keep client addresses for Rack::Attack and the audit
# log. No stickiness: sessions live in Redis.
all_load_balancers = [
  {
    region          = "us_east_1"
    resource_key    = "gitlab"
    name            = "gitlab"
    name_prefix     = null
    security_groups = ["sg-REPLACE-gitlab-lb"]
    subnets         = ["subnet-03a855e712be7b399", "subnet-0dbb7770d19f253ad"]
    subnet_mapping  = []

    access_logs                                                  = null
    client_keep_alive                                            = null
    connection_logs                                              = null
    customer_owned_ipv4_pool                                     = null
    desync_mitigation_mode                                       = null
    dns_record_client_routing_policy                             = null
    drop_invalid_header_fields                                   = null
    enable_cross_zone_load_balancing                             = true
    enable_deletion_protection                                   = false
    enable_http2                                                 = null
    enable_tls_version_and_cipher_suite_headers                  = null
    enable_waf_fail_open                                         = null
    enable_xff_client_port                                       = null
    enable_zonal_shift                                           = null
    enforce_security_group_inbound_rules_on_private_link_traffic = null
    health_check_logs                                            = null
    idle_timeout                                                 = null
    internal                                                     = true
    ip_address_type                                              = "ipv4"
    ipam_pools                                                   = null
    load_balancer_type                                           = "network"
    minimum_load_balancer_capacity                               = null
    preserve_host_header                                         = null
    secondary_ips_auto_assigned_per_subnet                       = null
    tags                                                         = {}
    timeouts                                                     = null
    xff_header_processing_mode                                   = null

    target_groups = [
      {
        resource_key = "rails-http"
        # Targets attach by Function tag within this VPC: both Rails nodes.
        function = "gitlab-rails"
        vpc_id   = "vpc-0724440de2891a1ee"
        port     = 80
        protocol = "TCP"
        # Short, so a destroy does not wait out the default five minutes.
        deregistration_delay              = 30
        protocol_version                  = null
        target_type                       = "instance"
        slow_start                        = null
        load_balancing_algorithm_type     = null
        load_balancing_anomaly_mitigation = null
        load_balancing_cross_zone_enabled = null
        preserve_client_ip                = "true"
        proxy_protocol_v2                 = null
        connection_termination            = null
        ip_address_type                   = null
        # Readiness without all=1: whether this node can serve, not whether the shared Redis,
        # Gitaly or database can, which would fail both targets at once.
        health_check = {
          enabled             = true
          healthy_threshold   = 2
          interval            = 10
          matcher             = "200"
          path                = "/-/readiness"
          port                = "traffic-port"
          protocol            = "HTTP"
          timeout             = 5
          unhealthy_threshold = 2
        }
        stickiness = null
        tags       = {}
      },
      {
        resource_key                      = "rails-ssh"
        function                          = "gitlab-rails"
        vpc_id                            = "vpc-0724440de2891a1ee"
        port                              = 2222
        protocol                          = "TCP"
        deregistration_delay              = 30
        protocol_version                  = null
        target_type                       = "instance"
        slow_start                        = null
        load_balancing_algorithm_type     = null
        load_balancing_anomaly_mitigation = null
        load_balancing_cross_zone_enabled = null
        preserve_client_ip                = "true"
        proxy_protocol_v2                 = null
        connection_termination            = null
        ip_address_type                   = null
        # The HTTP readiness on port 80, not a TCP check of 2222: gitlab-sshd answers while the
        # GitLab behind it is stopped.
        health_check = {
          enabled             = true
          healthy_threshold   = 2
          interval            = 10
          matcher             = "200"
          path                = "/-/readiness"
          port                = "80"
          protocol            = "HTTP"
          timeout             = 5
          unhealthy_threshold = 2
        }
        stickiness = null
        tags       = {}
      }
    ]

    listeners = [
      {
        resource_key                = "http"
        port                        = 80
        protocol                    = "TCP"
        ssl_policy                  = null
        alpn_policy                 = null
        certificate_arn             = null
        additional_certificate_arns = []
        default_action = {
          type             = "forward"
          target_group_key = "rails-http"
          redirect         = null
          fixed_response   = null
        }
        rules = []
      },
      {
        resource_key                = "ssh"
        port                        = 22
        protocol                    = "TCP"
        ssl_policy                  = null
        alpn_policy                 = null
        certificate_arn             = null
        additional_certificate_arns = []
        default_action = {
          type             = "forward"
          target_group_key = "rails-ssh"
          redirect         = null
          fixed_response   = null
        }
        rules = []
      }
    ]
  }
]
