# Module 1: Solving Multi-Cloud Security Consistency
## Lesson 1.1: Cross-Cloud Security Policy Standardization

### Policy Translation Framework (15 minutes)

#### AWS Security Groups ↔ Azure NSGs ↔ GCP Firewall Rules Mapping

**Understanding Platform-Specific Network Security Models:**

**AWS Security Groups Characteristics:**
- **Stateful Operation:** Automatically allows return traffic for established connections
- **Instance-Level Application:** Attached directly to EC2 instances or ENIs
- **Allow-Only Rules:** No explicit deny rules; traffic is denied by default
- **Rule Structure:** Protocol, port range, source (IP/CIDR/security group), description

```json
{
  "GroupName": "web-tier-sg",
  "Description": "Security group for web tier servers",
  "IpPermissions": [
    {
      "IpProtocol": "tcp",
      "FromPort": 80,
      "ToPort": 80,
      "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTP from internet"}]
    },
    {
      "IpProtocol": "tcp",
      "FromPort": 443,
      "ToPort": 443,
      "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "HTTPS from internet"}]
    }
  ]
}
```

**Azure Network Security Groups (NSGs) Characteristics:**
- **Stateful with Stateless Capability:** Can configure stateless rules if needed
- **Subnet or NIC-Level Application:** Can be applied to subnets or individual network interfaces
- **Allow and Deny Rules:** Explicit allow and deny rules with priority ordering
- **Default Rules:** Built-in default rules that can be overridden

```json
{
  "name": "web-tier-nsg",
  "properties": {
    "securityRules": [
      {
        "name": "AllowHTTP",
        "properties": {
          "priority": 100,
          "direction": "Inbound",
          "access": "Allow",
          "protocol": "Tcp",
          "sourceAddressPrefix": "*",
          "sourcePortRange": "*",
          "destinationAddressPrefix": "*",
          "destinationPortRange": "80"
        }
      },
      {
        "name": "AllowHTTPS",
        "properties": {
          "priority": 110,
          "direction": "Inbound",
          "access": "Allow",
          "protocol": "Tcp",
          "sourceAddressPrefix": "*",
          "sourcePortRange": "*",
          "destinationAddressPrefix": "*",
          "destinationPortRange": "443"
        }
      }
    ]
  }
}
```

**GCP Firewall Rules Characteristics:**
- **Stateful Operation:** Automatically handles return traffic
- **VPC-Level Application:** Applied to entire VPC with target-based filtering
- **Allow and Deny Rules:** Both allow and deny rules with priority-based precedence
- **Tag-Based Targeting:** Uses network tags for granular resource targeting

```json
{
  "name": "web-tier-firewall",
  "description": "Firewall rule for web tier servers",
  "direction": "INGRESS",
  "priority": 1000,
  "targetTags": ["web-server"],
  "sourceRanges": ["0.0.0.0/0"],
  "allowed": [
    {
      "IPProtocol": "tcp",
      "ports": ["80", "443"]
    }
  ]
}
```

**Cross-Platform Mapping Logic:**

Create a translation matrix that converts security intent across platforms:

| Security Intent | AWS Implementation | Azure Implementation | GCP Implementation |
|-----------------|-------------------|---------------------|-------------------|
| Allow HTTP from Internet | Security Group: Allow TCP/80 from 0.0.0.0/0 | NSG: Allow TCP/80 Inbound from Internet | Firewall: Allow TCP/80 from 0.0.0.0/0 |
| Allow SSH from Management Network | Security Group: Allow TCP/22 from 10.0.0.0/16 | NSG: Allow TCP/22 Inbound from 10.0.0.0/16 | Firewall: Allow TCP/22 from 10.0.0.0/16 |
| Deny All Other Traffic | Implicit (default deny) | Default rules + explicit deny | Implicit (default deny) |

#### IAM Policy Equivalency Across Platforms

**AWS IAM Policy Structure:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "S3ReadOnlyAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::company-data/*",
        "arn:aws:s3:::company-data"
      ],
      "Condition": {
        "StringEquals": {
          "s3:x-amz-server-side-encryption": "AES256"
        }
      }
    }
  ]
}
```

**Azure RBAC Policy Structure:**
```json
{
  "properties": {
    "roleName": "Storage Blob Data Reader Custom",
    "description": "Read access to blob data with encryption requirement",
    "assignableScopes": ["/subscriptions/{subscription-id}"],
    "permissions": [
      {
        "actions": [
          "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
          "Microsoft.Storage/storageAccounts/blobServices/containers/read"
        ],
        "notActions": [],
        "dataActions": [
          "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read"
        ],
        "notDataActions": [],
        "condition": "@Resource[Microsoft.Storage/storageAccounts:encryption.keySource] StringEquals 'Microsoft.Storage'"
      }
    ]
  }
}
```

**GCP IAM Policy Structure:**
```json
{
  "bindings": [
    {
      "role": "roles/storage.objectViewer",
      "members": [
        "user:employee@company.com"
      ],
      "condition": {
        "title": "Encrypted Objects Only",
        "description": "Access only to encrypted objects",
        "expression": "resource.name.startsWith('projects/_/buckets/company-data/') && resource.service == 'storage.googleapis.com'"
      }
    }
  ]
}
```

**Permission Equivalency Table:**

| Common Permission | AWS Action | Azure Action | GCP Role |
|-------------------|------------|--------------|----------|
| Read Object Storage | s3:GetObject | Microsoft.Storage/.../blobs/read | storage.objectViewer |
| List Storage Containers | s3:ListBucket | Microsoft.Storage/.../containers/read | storage.objectViewer |
| Create Virtual Machine | ec2:RunInstances | Microsoft.Compute/virtualMachines/write | compute.instanceAdmin.v1 |
| Manage Network Security | ec2:AuthorizeSecurityGroupIngress | Microsoft.Network/networkSecurityGroups/write | compute.securityAdmin |

#### Compliance Control Mapping (SOC2, PCI-DSS Cross-Platform)

**SOC 2 Type II Control Mapping:**

**CC6.1 - Logical and Physical Access Controls:**

| Control Requirement | AWS Implementation | Azure Implementation | GCP Implementation |
|--------------------|--------------------|---------------------|-------------------|
| Network segmentation | VPC + Security Groups + NACLs | VNet + NSGs + Application Security Groups | VPC + Firewall Rules + Private Google Access |
| Access logging | CloudTrail + VPC Flow Logs | Activity Logs + NSG Flow Logs | Cloud Audit Logs + VPC Flow Logs |
| Multi-factor authentication | IAM MFA + AWS SSO | Azure AD MFA + Conditional Access | Cloud Identity + 2-Step Verification |

**CC6.7 - Data Transmission Controls:**

```yaml
# Cross-platform encryption in transit policy
encryption_in_transit:
  aws:
    - enforce_ssl_only: true
    - min_tls_version: "1.2"
    - certificate_authority: "AWS Certificate Manager"
  azure:
    - require_secure_transfer: true
    - min_tls_version: "1.2"
    - certificate_source: "Azure Key Vault"
  gcp:
    - ssl_policy: "STRONG"
    - min_tls_version: "TLS_1_2"
    - certificate_manager: "Google-managed SSL"
```

**PCI DSS Control Mapping:**

**Requirement 1 - Install and maintain a firewall configuration:**

| PCI DSS Control | AWS Configuration | Azure Configuration | GCP Configuration |
|-----------------|-------------------|---------------------|-------------------|
| 1.1.4 - Current network diagram | VPC diagrams with Security Groups | Virtual Network topology with NSGs | VPC network diagram with firewall rules |
| 1.2.1 - Restrict inbound/outbound traffic | Security Groups + NACLs | NSGs + Azure Firewall | VPC firewall rules + Cloud NAT |
| 1.3.4 - Do not allow direct public access | Private subnets + NAT Gateway | Private subnets + NAT Gateway | Private Google Access + Cloud NAT |

**Requirement 7 - Restrict access to cardholder data by business need to know:**

```json
{
  "compliance_control": "PCI_DSS_7.1",
  "description": "Limit access to system components and cardholder data",
  "implementations": {
    "aws": {
      "policies": ["least_privilege_iam", "resource_based_policies"],
      "services": ["IAM", "Organizations", "Control Tower"]
    },
    "azure": {
      "policies": ["rbac_assignments", "pim_eligible_assignments"],
      "services": ["Azure AD", "Azure RBAC", "Privileged Identity Management"]
    },
    "gcp": {
      "policies": ["iam_conditions", "resource_hierarchy"],
      "services": ["Cloud IAM", "Resource Manager", "Identity-Aware Proxy"]
    }
  }
}
```

### Unified Policy Template Development (15 minutes)

#### JSON/YAML-Based Cross-Platform Policy Definitions

**Universal Security Policy Schema:**

Design a vendor-neutral schema that captures security requirements without platform-specific syntax:

```yaml
# Universal Security Policy Definition
apiVersion: security.policy/v1
kind: SecurityPolicy
metadata:
  name: web-tier-security
  description: "Standard security policy for web tier applications"
  compliance_frameworks: ["SOC2", "PCI-DSS"]
  
spec:
  network_security:
    ingress_rules:
      - name: "allow_http_https"
        protocol: tcp
        ports: [80, 443]
        sources: 
          - cidr: "0.0.0.0/0"
        description: "Allow HTTP/HTTPS from internet"
        
      - name: "allow_ssh_management"
        protocol: tcp
        ports: [22]
        sources:
          - cidr: "10.0.0.0/8"
          - tag: "management_network"
        description: "Allow SSH from management networks"
        
    egress_rules:
      - name: "allow_outbound_web"
        protocol: tcp
        ports: [80, 443]
        destinations:
          - cidr: "0.0.0.0/0"
        description: "Allow outbound web traffic"
        
  identity_access:
    roles:
      - name: "web_server_role"
        permissions:
          - resource_type: "storage"
            actions: ["read", "list"]
            resources: ["arn:*:storage:::app-data/*"]
            conditions:
              encryption_required: true
              
      - name: "web_admin_role"
        permissions:
          - resource_type: "compute"
            actions: ["start", "stop", "restart"]
            resources: ["tag:Environment=Production"]
            
  compliance_controls:
    data_encryption:
      at_rest: 
        enabled: true
        algorithm: "AES-256"
        key_management: "cloud_managed"
      in_transit:
        enabled: true
        min_tls_version: "1.2"
        
    audit_logging:
      enabled: true
      retention_days: 2555  # 7 years for PCI compliance
      integrity_protection: true
      
    access_controls:
      mfa_required: true
      session_timeout: 3600  # 1 hour
      password_policy:
        min_length: 14
        complexity: true
        rotation_days: 90
```

**Policy Transformation Engine:**

Create transformation logic that converts universal policies to platform-specific configurations:

```python
# Policy Translation Engine (Pseudo-code)
class PolicyTranslator:
    def __init__(self):
        self.aws_translator = AWSPolicyTranslator()
        self.azure_translator = AzurePolicyTranslator()
        self.gcp_translator = GCPPolicyTranslator()
    
    def translate_policy(self, universal_policy, target_platforms):
        translated_policies = {}
        
        for platform in target_platforms:
            if platform == "aws":
                translated_policies["aws"] = self.aws_translator.translate(universal_policy)
            elif platform == "azure":
                translated_policies["azure"] = self.azure_translator.translate(universal_policy)
            elif platform == "gcp":
                translated_policies["gcp"] = self.gcp_translator.translate(universal_policy)
                
        return translated_policies

class AWSPolicyTranslator:
    def translate(self, policy):
        aws_config = {
            "security_groups": self._translate_network_rules(policy.network_security),
            "iam_policies": self._translate_iam_rules(policy.identity_access),
            "config_rules": self._translate_compliance_controls(policy.compliance_controls)
        }
        return aws_config
    
    def _translate_network_rules(self, network_security):
        security_groups = []
        for rule in network_security.ingress_rules:
            sg_rule = {
                "IpProtocol": rule.protocol,
                "FromPort": min(rule.ports),
                "ToPort": max(rule.ports),
                "IpRanges": [{"CidrIp": src.cidr} for src in rule.sources if hasattr(src, 'cidr')]
            }
            security_groups.append(sg_rule)
        return security_groups
```

#### Terraform Modules for Consistent Security Controls

**Multi-Cloud Security Module Structure:**

```hcl
# modules/multi-cloud-security/main.tf
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

# Variables for universal policy definition
variable "security_policy" {
  description = "Universal security policy definition"
  type = object({
    name = string
    network_security = object({
      ingress_rules = list(object({
        name        = string
        protocol    = string
        ports       = list(number)
        sources     = list(object({
          cidr = optional(string)
          tag  = optional(string)
        }))
        description = string
      }))
      egress_rules = list(object({
        name         = string
        protocol     = string
        ports        = list(number)
        destinations = list(object({
          cidr = optional(string)
          tag  = optional(string)
        }))
        description = string
      }))
    })
    identity_access = object({
      roles = list(object({
        name = string
        permissions = list(object({
          resource_type = string
          actions      = list(string)
          resources    = list(string)
          conditions   = optional(map(any))
        }))
      }))
    })
  })
}

variable "cloud_platforms" {
  description = "List of cloud platforms to deploy to"
  type        = list(string)
  default     = ["aws", "azure", "gcp"]
}

# AWS Security Group Module
module "aws_security" {
  count  = contains(var.cloud_platforms, "aws") ? 1 : 0
  source = "./aws"
  
  security_policy = var.security_policy
  vpc_id         = var.aws_vpc_id
  
  providers = {
    aws = aws
  }
}

# Azure NSG Module  
module "azure_security" {
  count  = contains(var.cloud_platforms, "azure") ? 1 : 0
  source = "./azure"
  
  security_policy      = var.security_policy
  resource_group_name = var.azure_resource_group_name
  location           = var.azure_location
  
  providers = {
    azurerm = azurerm
  }
}

# GCP Firewall Module
module "gcp_security" {
  count  = contains(var.cloud_platforms, "gcp") ? 1 : 0
  source = "./gcp"
  
  security_policy = var.security_policy
  project_id     = var.gcp_project_id
  network_name   = var.gcp_network_name
  
  providers = {
    google = google
  }
}
```

**AWS-Specific Module Implementation:**

```hcl
# modules/multi-cloud-security/aws/main.tf
resource "aws_security_group" "main" {
  name_prefix = "${var.security_policy.name}-"
  description = "Security group for ${var.security_policy.name}"
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.security_policy.network_security.ingress_rules
    content {
      description = ingress.value.description
      from_port   = min(ingress.value.ports...)
      to_port     = max(ingress.value.ports...)
      protocol    = ingress.value.protocol
      cidr_blocks = [
        for source in ingress.value.sources : 
        source.cidr if source.cidr != null
      ]
    }
  }

  dynamic "egress" {
    for_each = var.security_policy.network_security.egress_rules
    content {
      description = egress.value.description
      from_port   = min(egress.value.ports...)
      to_port     = max(egress.value.ports...)
      protocol    = egress.value.protocol
      cidr_blocks = [
        for destination in egress.value.destinations : 
        destination.cidr if destination.cidr != null
      ]
    }
  }

  tags = {
    Name   = var.security_policy.name
    Source = "multi-cloud-security-module"
  }
}

# IAM Policies from universal definition
resource "aws_iam_policy" "service_policies" {
  count = length(var.security_policy.identity_access.roles)
  name  = "${var.security_policy.name}-${var.security_policy.identity_access.roles[count.index].name}"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      for permission in var.security_policy.identity_access.roles[count.index].permissions : {
        Effect = "Allow"
        Action = [
          for action in permission.actions :
          "${permission.resource_type}:${title(action)}"
        ]
        Resource = permission.resources
        Condition = permission.conditions != null ? permission.conditions : {}
      }
    ]
  })
}
```

**Azure-Specific Module Implementation:**

```hcl
# modules/multi-cloud-security/azure/main.tf
resource "azurerm_network_security_group" "main" {
  name                = "${var.security_policy.name}-nsg"
  location            = var.location
  resource_group_name = var.resource_group_name

  dynamic "security_rule" {
    for_each = { for idx, rule in var.security_policy.network_security.ingress_rules : idx => rule }
    content {
      name                       = security_rule.value.name
      priority                   = 100 + security_rule.key * 10
      direction                  = "Inbound"
      access                     = "Allow"
      protocol                   = title(security_rule.value.protocol)
      source_port_range          = "*"
      destination_port_ranges    = [for port in security_rule.value.ports : tostring(port)]
      source_address_prefixes    = [
        for source in security_rule.value.sources : 
        source.cidr if source.cidr != null
      ]
      destination_address_prefix = "*"
      description                = security_rule.value.description
    }
  }

  tags = {
    Source = "multi-cloud-security-module"
  }
}

# Azure RBAC Role Definitions
resource "azurerm_role_definition" "service_roles" {
  count = length(var.security_policy.identity_access.roles)
  name  = "${var.security_policy.name}-${var.security_policy.identity_access.roles[count.index].name}"
  scope = "/subscriptions/${data.azurerm_subscription.current.subscription_id}"

  permissions {
    actions = [
      for permission in var.security_policy.identity_access.roles[count.index].permissions :
      "Microsoft.${title(permission.resource_type)}/*/${join("/", permission.actions)}"
    ]
  }

  assignable_scopes = [
    "/subscriptions/${data.azurerm_subscription.current.subscription_id}"
  ]
}
```

#### Cloud-Agnostic Security Baseline Implementation

**Security Baseline Configuration Template:**

```yaml
# security-baseline.yaml
apiVersion: security.baseline/v1
kind: SecurityBaseline
metadata:
  name: enterprise-security-baseline
  version: "2.1.0"
  compliance_frameworks: ["CIS", "SOC2", "PCI-DSS", "ISO27001"]

spec:
  network_security:
    default_deny_all: true
    allowed_protocols: ["tcp", "udp", "icmp"]
    prohibited_ports: [23, 135, 139, 445, 1433, 1521, 3389]
    
    encryption_requirements:
      in_transit:
        enforce: true
        min_tls_version: "1.2"
        cipher_suites: ["ECDHE-RSA-AES256-GCM-SHA384", "ECDHE-RSA-AES128-GCM-SHA256"]
      at_rest:
        enforce: true
        algorithms: ["AES-256", "ChaCha20-Poly1305"]
        key_rotation_days: 90

  identity_management:
    authentication:
      mfa_required: true
      password_policy:
        min_length: 14
        require_special_chars: true
        require_numbers: true
        require_uppercase: true
        require_lowercase: true
        rotation_days: 90
        history_count: 12
      session_management:
        timeout_minutes: 60
        concurrent_sessions: 3
        idle_timeout_minutes: 30

    authorization:
      least_privilege: true
      just_in_time_access: true
      regular_access_reviews:
        frequency_days: 90
        automated_removal: true

  audit_logging:
    enabled: true
    log_retention_days: 2555  # 7 years
    integrity_protection: true
    real_time_monitoring: true
    
    required_events:
      - authentication_events
      - authorization_changes
      - resource_access
      - configuration_changes
      - administrative_actions
      - failed_access_attempts

  data_protection:
    classification_required: true
    encryption_at_rest: true
    encryption_in_transit: true
    backup_encryption: true
    
    retention_policies:
      pci_data: 2555  # 7 years
      audit_logs: 2555  # 7 years
      general_data: 1095  # 3 years

  vulnerability_management:
    continuous_scanning: true
    patch_management:
      critical_patches: 7  # days
      high_patches: 30     # days
      medium_patches: 90   # days
    
    security_assessments:
      frequency_days: 90
      penetration_testing: 365  # annually
```

**Baseline Implementation Terraform Module:**

```hcl
# modules/security-baseline/main.tf
locals {
  baseline_config = yamldecode(file("${path.module}/security-baseline.yaml"))
}

# AWS Config Rules for baseline compliance
resource "aws_config_configuration_recorder" "baseline" {
  count    = contains(var.target_platforms, "aws") ? 1 : 0
  name     = "security-baseline-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_config_rule" "security_baseline_rules" {
  count = contains(var.target_platforms, "aws") ? length(local.baseline_rules) : 0
  
  name = local.baseline_rules[count.index].name

  source {
    owner             = "AWS"
    source_identifier = local.baseline_rules[count.index].source_identifier
  }

  depends_on = [aws_config_configuration_recorder.baseline]
}

# Azure Policy for baseline compliance
resource "azurerm_policy_definition" "security_baseline" {
  count        = contains(var.target_platforms, "azure") ? 1 : 0
  name         = "enterprise-security-baseline"
  policy_type  = "Custom"
  mode         = "All"
  display_name = "Enterprise Security Baseline"

  policy_rule = jsonencode({
    if = {
      allOf = [
        {
          field  = "type"
          equals = "Microsoft.Compute/virtualMachines"
        }
      ]
    }
    then = {
      effect = "auditIfNotExists"
      details = {
        type = "Microsoft.Compute/virtualMachines/extensions"
        existenceCondition = {
          allOf = [
            {
              field  = "Microsoft.Compute/virtualMachines/extensions/publisher"
              equals = "Microsoft.Azure.Security"
            }
          ]
        }
      }
    }
  })
}

# GCP Organization Policies for baseline compliance  
resource "google_organization_policy" "baseline_policies" {
  count      = contains(var.target_platforms, "gcp") ? length(local.gcp_baseline_policies) : 0
  org_id     = var.gcp_organization_id
  constraint = local.gcp_baseline_policies[count.index].constraint

  dynamic "boolean_policy" {
    for_each = local.gcp_baseline_policies[count.index].type == "boolean" ? [1] : []
    content {
      enforced = local.gcp_baseline_policies[count.index].enforced
    }
  }

  dynamic "list_policy" {
    for_each = local.gcp_baseline_policies[count.index].type == "list" ? [1] : []
    content {
      inherit_from_parent = false
      suggested_value     = local.gcp_baseline_policies[count.index].suggested_value
      
      dynamic "allow" {
        for_each = local.gcp_baseline_policies[count.index].allowed_values != null ? [1] : []
        content {
          values = local.gcp_baseline_policies[count.index].allowed_values
        }
      }
    }
  }
}

locals {
  baseline_rules = [
    {
      name                = "encrypted-volumes"
      source_identifier  = "ENCRYPTED_VOLUMES"
    },
    {
      name                = "root-mfa-enabled"
      source_identifier  = "ROOT_MFA_ENABLED"
    },
    {
      name                = "s3-bucket-ssl-requests-only"
      source_identifier  = "S3_BUCKET_SSL_REQUESTS_ONLY"
    }
  ]
  
  gcp_baseline_policies = [
    {
      constraint      = "constraints/compute.requireOsLogin"
      type           = "boolean"
      enforced       = true
    },
    {
      constraint      = "constraints/sql.restrictPublicIp"
      type           = "boolean"
      enforced       = true
    },
    {
      constraint      = "constraints/storage.uniformBucketLevelAccess"
      type           = "boolean"
      enforced       = true
    }
  ]
}
```

### Image Suggestions

1. **Policy Translation Flow Diagram**: Visual flowchart showing how a universal security policy gets translated into AWS Security Groups, Azure NSGs, and GCP Firewall Rules, with specific examples of rule mappings

2. **IAM Equivalency Matrix**: Side-by-side comparison table/chart showing equivalent permissions across AWS IAM, Azure RBAC, and GCP Cloud IAM with color-coded mapping relationships

3. **Compliance Control Dashboard**: Mock-up dashboard showing SOC 2 and PCI DSS compliance status across all three cloud platforms with unified reporting metrics

4. **Terraform Module Architecture**: Technical diagram illustrating the modular structure of the multi-cloud security Terraform modules, showing how universal policy definitions flow through platform-specific implementations

5. **Security Baseline Implementation Pipeline**: DevOps pipeline visualization showing how security baselines are automatically deployed and enforced across multiple cloud platforms using Infrastructure as Code
