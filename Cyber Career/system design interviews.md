# 40 Security-Focused System Design Questions for Big Tech Interviews

Organized by difficulty and security domain. Each question includes scope, evaluation criteria, and expected depth.

---

## 🎯 **HOW TO APPROACH THESE QUESTIONS**

### **Standard Framework (Use for Every Question):**

```
1. REQUIREMENTS CLARIFICATION (5 min)
   - Scale (users, requests, data volume)
   - Security requirements (compliance, threat model)
   - Performance requirements (latency, availability)
   - Constraints (budget, technology, timeline)

2. HIGH-LEVEL DESIGN (15 min)
   - Architecture diagram with components
   - Data flow with trust boundaries
   - Key technologies and why

3. DEEP DIVE (25 min)
   - Security controls at each layer
   - Threat modeling (what can go wrong?)
   - Authentication & authorization
   - Encryption & key management
   - Monitoring & detection
   - Incident response considerations

4. TRADE-OFFS & SCALING (10 min)
   - Security vs performance vs cost
   - How to scale (horizontal/vertical)
   - Failure modes and recovery
   - Operational complexity

5. METRICS & VALIDATION (5 min)
   - How do you measure success?
   - What metrics matter?
   - How do you know it's secure?
```

---

## 📁 **CATEGORY 1: AUTHENTICATION & IDENTITY (8 questions)**

### **Q1. Design a Secure Authentication System for a Multi-Tenant SaaS**

**Scope:**
- 50,000 companies (tenants)
- 5M users total
- Must support: password auth, SSO (SAML/OIDC), MFA
- Mobile + web clients
- High availability required

**Key Discussion Points:**
```
Authentication Methods:
- Password + MFA (TOTP, SMS, push)
- SSO integration (SAML 2.0, OIDC)
- API tokens for programmatic access
- Certificate-based auth for services

Session Management:
- JWT vs opaque tokens (trade-offs)
- Refresh token rotation
- Session invalidation strategies
- Token storage (cookies vs localStorage)

Tenant Isolation:
- Database-level isolation vs row-level
- Subdomain routing vs path-based
- Cross-tenant access prevention
- Tenant context propagation

Security Controls:
- Rate limiting (per user, per tenant, global)
- Brute force protection
- Account takeover detection
- Device fingerprinting
- Anomaly detection

Threat Model:
- Credential stuffing
- Token theft
- Session fixation
- Phishing
- Insider threats
- Account enumeration
```

**Evaluation Criteria:**
- ✅ Mentions multiple auth methods
- ✅ Discusses session security (JWT considerations)
- ✅ Addresses tenant isolation clearly
- ✅ Includes detection/monitoring
- ✅ Considers threat scenarios without prompting

---

### **Q2. Design a Secrets Management Service (like HashiCorp Vault)**

**Scope:**
- Store secrets (API keys, passwords, certificates)
- 10,000 applications requesting secrets
- 100,000 secrets stored
- Must support secret rotation
- Audit every access

**Key Discussion Points:**
```
Architecture:
┌─────────────┐
│   Clients   │ (Apps, Users)
│ (mTLS auth) │
└──────┬──────┘
       │
┌──────▼──────────┐
│  API Gateway    │ ← AuthN, Rate Limiting
│ (Load Balanced) │
└──────┬──────────┘
       │
┌──────▼──────────┐
│ Secrets Service │ ← AuthZ, Audit Logging
└──────┬──────────┘
       │
┌──────▼──────────┐
│ Encrypted Store │ ← Encryption at rest
│   (Backend DB)  │
└──────┬──────────┘
       │
┌──────▼──────────┐
│   HSM / KMS     │ ← Master key storage
└─────────────────┘

Authentication:
- mTLS for service-to-service
- OAuth2/OIDC for users
- AppRole for applications
- Kubernetes auth for K8s pods

Authorization:
- Path-based policies
- Role-based access control (RBAC)
- Least privilege enforcement
- Time-bound credentials

Encryption:
- Encryption at rest (AES-256-GCM)
- Transit encryption (TLS 1.3)
- Envelope encryption pattern
- Master key in HSM/KMS
- Key rotation strategy

Secret Types:
- Static secrets (passwords, API keys)
- Dynamic secrets (DB credentials, cloud IAM)
- Encryption as a service
- Certificate management

Rotation:
- Automated rotation schedules
- Zero-downtime rotation
- Notification on rotation
- Rollback capability

Audit & Compliance:
- Log every access (who, what, when)
- Immutable audit logs
- Anomaly detection
- Compliance reports (SOC2, PCI-DSS)

High Availability:
- Multi-region replication
- Consistency model (strong vs eventual)
- Disaster recovery
- Backup encryption

Threat Model:
- Compromised client credentials
- Insider threat (admin abuse)
- Network interception
- Storage breach
- Side-channel attacks
- Seal/unseal security
```

**Expected Depth:**
- Master key protection (HSM vs KMS)
- Envelope encryption explanation
- Seal/unseal mechanism
- Dynamic secrets generation
- Audit log immutability

---

### **Q3. Design OAuth2 Authorization Server at Scale**

**Scope:**
- 1M registered applications
- 100M users
- Support all OAuth2 flows
- OpenID Connect support
- Token introspection at high QPS

**Key Discussion Points:**
```
OAuth2 Flows to Support:
- Authorization Code (with PKCE)
- Client Credentials
- Refresh Token
- Device Flow

Token Management:
- JWT vs reference tokens
- Token signing (RSA, ECDSA)
- Token expiration strategy
- Refresh token rotation
- Token revocation

Scaling Considerations:
- Stateless architecture
- Token validation without DB lookup
- Caching strategies
- Rate limiting per client

Security:
- PKCE enforcement for public clients
- State parameter validation
- Redirect URI validation
- Scope enforcement
- Token binding
```

**Twist Questions:**
- "How do you handle token revocation in a stateless system?"
- "How do you prevent authorization code interception?"
- "Design for 1M token validations per second"

---

### **Q4. Design Single Sign-On (SSO) System for Enterprise**

**Scope:**
- 100 integrated applications
- 50,000 employees
- Must support SAML and OIDC
- Session management across apps
- MFA enforcement

**Key Discussion Points:**
```
Architecture:
- Identity Provider (IdP) design
- Service Provider (SP) integration
- Session federation
- Attribute mapping

SAML Flow:
- SP-initiated vs IdP-initiated
- Assertion signing and encryption
- Metadata exchange
- Clock skew handling

OIDC Flow:
- Discovery mechanism
- UserInfo endpoint design
- ID token vs access token

Session Management:
- Global session at IdP
- Local sessions at SPs
- Single logout (SLO) implementation
- Session timeout policies

MFA Integration:
- Adaptive MFA (risk-based)
- Remember device
- Step-up authentication
- MFA bypass for trusted networks

Security:
- SAML assertion replay prevention
- XML signature validation
- Redirect validation
- Cross-site request forgery protection
```

---

### **Q5. Design Passwordless Authentication System**

**Scope:**
- Support WebAuthn/FIDO2
- Magic links via email
- Biometric authentication
- Fallback mechanisms
- 10M users

**Key Discussion Points:**
```
WebAuthn/FIDO2:
- Registration ceremony
- Authentication ceremony
- Credential storage
- Attestation validation
- Resident vs non-resident keys

Magic Links:
- Token generation (cryptographically secure)
- Time-bound expiration
- Single-use tokens
- Rate limiting (prevent enumeration)

Biometrics:
- Platform authenticator vs roaming
- Biometric template storage
- Liveness detection
- Privacy considerations

Account Recovery:
- Recovery codes
- Trusted device
- Secondary email/phone
- Identity verification

Threat Model:
- Phishing resistance
- Man-in-the-middle
- Device loss
- Biometric spoofing
```

---

### **Q6. Design Multi-Factor Authentication (MFA) Service**

**Scope:**
- Support TOTP, SMS, push notifications, hardware tokens
- 50M users
- Low-latency verification
- High availability

**Key Discussion Points:**
```
MFA Methods:
- TOTP (Time-based One-Time Password)
- SMS (despite known weaknesses)
- Push notifications (approve/deny)
- Hardware tokens (YubiKey, RSA)
- Backup codes

TOTP Implementation:
- Secret generation and storage
- Clock drift tolerance (±1 window)
- QR code generation
- Seed backup/recovery

Push Notification:
- Challenge-response mechanism
- Number matching (prevent fatigue attacks)
- Device registration
- Notification expiration

Verification Flow:
- Challenge generation
- Rate limiting (prevent brute force)
- Attempt tracking
- Lockout policy

User Experience:
- Remember device (30 days)
- Risk-based MFA (adaptive)
- Step-up authentication
- Fallback methods

Availability:
- What if SMS provider is down?
- Multiple enrolled devices
- Backup codes always available
- Graceful degradation

Security:
- Prevent MFA fatigue attacks
- SIM swap protection
- Push bombing mitigation
- Backup code generation (cryptographically secure)
```

---

### **Q7. Design Identity and Access Management (IAM) System for Cloud Provider**

**Scope:**
- Like AWS IAM
- 1M customers with 10M users/roles
- Fine-grained permissions
- Cross-account access
- Service-to-service auth

**Key Discussion Points:**
```
Core Concepts:
- Users, Groups, Roles
- Policies (identity-based, resource-based)
- Permission boundaries
- Service Control Policies (SCPs)

Policy Evaluation:
- Explicit deny > explicit allow > implicit deny
- Policy inheritance
- Permission boundaries enforcement
- Condition evaluation (IP, time, MFA)

Roles & Temporary Credentials:
- AssumeRole mechanism
- STS (Security Token Service)
- Credential vending
- Credential rotation

Cross-Account Access:
- Trust relationships
- External ID for third-party access
- Role chaining limits

Performance:
- Policy evaluation at scale (millions of requests/sec)
- Caching strategies
- Distributed authorization
- Eventual consistency trade-offs

Audit:
- CloudTrail equivalent
- Who accessed what resource?
- Permission changes tracking
- Compliance reporting
```

---

### **Q8. Design Certificate Management System (like Let's Encrypt)**

**Scope:**
- Issue TLS certificates
- Automatic renewal
- 100M domains
- ACME protocol support
- Certificate revocation

**Key Discussion Points:**
```
Certificate Issuance:
- ACME protocol flow
- Domain validation (HTTP-01, DNS-01, TLS-ALPN-01)
- Certificate signing
- Root CA protection

Renewal:
- Automated renewal (30 days before expiry)
- Renewal rate limiting
- Batch renewal optimization

Revocation:
- CRL (Certificate Revocation List)
- OCSP (Online Certificate Status Protocol)
- OCSP stapling
- Revocation reasons

CA Infrastructure:
- Root CA (offline, HSM-protected)
- Intermediate CAs
- Certificate transparency logs
- Key ceremony procedures

Scaling:
- Issuance throughput (certificates/sec)
- Validation parallelization
- Geographic distribution
- CDN for CRL/OCSP

Security:
- HSM for private key protection
- Rate limiting (prevent abuse)
- Domain validation security
- Certificate transparency monitoring
```

---

## ☁️ **CATEGORY 2: CLOUD SECURITY ARCHITECTURES (8 questions)**

### **Q9. Design Cloud Security Monitoring Platform (CSPM)**

**Scope:**
- Monitor 1,000+ AWS/Azure/GCP accounts
- Real-time misconfiguration detection
- Compliance reporting (CIS, PCI-DSS, SOC2)
- Automated remediation

**Key Discussion Points:**
```
Architecture:
┌──────────────┐
│ Cloud APIs   │ (AWS, Azure, GCP)
└──────┬───────┘
       │
┌──────▼───────┐
│  Collectors  │ ← Pull configs periodically
│  (Lambda/    │
│   Functions) │
└──────┬───────┘
       │
┌──────▼───────┐
│  Message     │ ← Kinesis/Kafka/EventHub
│  Queue       │
└──────┬───────┘
       │
┌──────▼───────┐
│  Detection   │ ← Rule engine
│  Engine      │
└──────┬───────┘
       │
┌──────▼───────┐
│  Storage     │ ← Historical data
│  (S3/Blob)   │
└──────┬───────┘
       │
┌──────▼───────┐
│  Dashboard   │ ← Visualization
│  & Alerts    │
└──────────────┘

Data Collection:
- API polling (CloudTrail, Config, Activity Logs)
- Event-driven (CloudWatch Events, EventGrid)
- Agent-based (for deep inspection)
- Change detection (compare snapshots)

Detection Rules:
- S3 buckets public
- Security groups allow 0.0.0.0/0 on port 22
- IAM policies too permissive
- Encryption disabled
- Logging not enabled
- Unused resources (security risk)

Rule Engine:
- Rule format (YAML, Python, Rego)
- Custom rules support
- Rule versioning
- False positive handling

Remediation:
- Manual remediation workflows
- Automated remediation (Lambda, Azure Functions)
- Rollback capability
- Approval workflows for sensitive changes

Compliance:
- Map findings to frameworks (CIS, NIST, PCI)
- Compliance scoring
- Historical compliance trends
- Report generation

Multi-Cloud:
- Unified data model
- Cloud-specific collectors
- Cross-cloud correlation
- Vendor-agnostic rules where possible

Scaling:
- Handle 1M+ resources
- Real-time processing
- Historical data retention
- Query performance
```

**Expected Depth:**
- Specific AWS/Azure/GCP APIs to call
- Rule evaluation optimization
- False positive reduction strategies
- Remediation safety mechanisms

---

### **Q10. Design Secure Multi-Tenant Cloud Infrastructure**

**Scope:**
- SaaS platform with 10,000 tenants
- Each tenant has isolated compute, storage, network
- Must prevent cross-tenant access
- Performance isolation required

**Key Discussion Points:**
```
Isolation Strategies:

1. Data Plane Isolation:
   - Separate VPCs per tenant (expensive)
   - Shared VPC with network segmentation
   - Application-level isolation (tenant_id)
   - Database: separate DBs vs schema vs row-level

2. Compute Isolation:
   - Dedicated instances per tenant
   - Kubernetes namespaces + network policies
   - Serverless with IAM boundaries
   - Container isolation

3. Network Isolation:
   - VPC peering vs Transit Gateway
   - Security groups per tenant
   - Private Link for service access
   - Network policies in K8s

4. Storage Isolation:
   - Separate S3 buckets with bucket policies
   - KMS keys per tenant
   - Encryption with tenant-specific keys
   - Access logging per tenant

Identity & Access:
- Tenant-specific IAM roles
- Role assumption patterns
- Service account per tenant
- Least privilege enforcement

Monitoring & Logging:
- Tenant-specific log streams
- Audit trail per tenant
- Anomaly detection per tenant
- Cross-tenant access alerting

Threat Model:
- Malicious tenant attacks another tenant
- Compromised tenant spreads to others
- Noisy neighbor (resource exhaustion)
- Privilege escalation across tenants
- Data leakage between tenants

Cost vs Security:
- Full isolation (expensive, secure)
- Logical isolation (cheaper, more risk)
- Hybrid approach (tier-based)

Scaling:
- Onboarding new tenants
- Tenant lifecycle management
- Resource quotas per tenant
- Performance SLAs
```

---

### **Q11. Design Kubernetes Security Platform**

**Scope:**
- 1,000 Kubernetes clusters
- Multi-tenant clusters
- Runtime security monitoring
- Policy enforcement
- Vulnerability management

**Key Discussion Points:**
```
Cluster Security:
- RBAC configuration
- Network policies (Calico, Cilium)
- Pod Security Standards/Policies
- Admission controllers
- API server hardening

Workload Security:
- Image scanning (Trivy, Clair)
- Runtime security (Falco)
- Secrets management (sealed secrets, external secrets)
- Service mesh (Istio, Linkerd) for mTLS
- Sidecar injection

Network Security:
- Network policies (default deny)
- Service mesh for E2E encryption
- Ingress security (WAF)
- Egress filtering

Policy Enforcement:
- OPA/Gatekeeper for admission control
- Deny privileged pods
- Enforce resource limits
- Require security context
- Image registry whitelisting

Monitoring:
- Audit logging
- Anomaly detection (unusual API calls)
- Runtime threat detection
- Vulnerability scanning
- Compliance checking

Multi-tenancy:
- Namespace isolation
- Resource quotas
- Network policies between namespaces
- Separate node pools
- Tenant-specific RBAC

Threat Detection:
- Privilege escalation attempts
- Unusual process execution
- Outbound connections to C2
- Crypto mining detection
- Container escape attempts
```

---

### **Q12. Design Serverless Security Architecture**

**Scope:**
- 10,000 Lambda functions (or equivalent)
- Event-driven architecture
- Secrets management
- Third-party dependencies
- Cold start security

**Key Discussion Points:**
```
Function Security:
- Least privilege IAM roles per function
- Resource-based policies
- Environment variable encryption
- Layer security (shared code)
- VPC configuration (when needed)

Secrets Management:
- AWS Secrets Manager / Parameter Store
- Injecting secrets at runtime
- Avoiding hardcoded credentials
- Secret rotation handling

Dependency Management:
- Third-party library scanning
- Lock file enforcement
- Vulnerability scanning in CI/CD
- Supply chain security

API Security:
- API Gateway with WAF
- Rate limiting
- Authentication (Cognito, custom authorizers)
- Request validation
- Throttling

Event Sources:
- SQS, SNS, EventBridge security
- Event source validation
- Dead letter queues
- Poison message handling

Monitoring:
- CloudWatch logs analysis
- X-Ray tracing for security
- Anomaly detection (unusual invocations)
- Cost anomalies (crypto mining indicator)

Cold Start Security:
- Initialization security
- Secret fetching optimization
- Warmed pool management

Threat Model:
- Function compromise via dependency
- Privilege escalation
- Data exfiltration
- Resource abuse (crypto mining)
- Injection attacks via event data
```

---

### **Q13. Design Cloud Data Loss Prevention (DLP) System**

**Scope:**
- Scan data in S3, databases, SaaS apps
- Detect PII, PHI, financial data, secrets
- Real-time and batch scanning
- Automated response actions

**Key Discussion Points:**
```
Data Sources:
- Object storage (S3, Blob, GCS)
- Databases (RDS, DynamoDB, SQL)
- SaaS apps (Salesforce, Office 365)
- Network traffic (inline DLP)
- Endpoints (agent-based)

Detection Methods:
- Pattern matching (regex for SSN, CC numbers)
- Fingerprinting (exact/partial match)
- Machine learning (context-aware)
- Named entity recognition (NER)

Data Types to Detect:
- PII (SSN, passport, driver's license)
- PHI (medical records)
- Financial (credit cards, bank accounts)
- Secrets (API keys, passwords)
- Intellectual property

Architecture:
┌──────────────┐
│ Data Sources │
└──────┬───────┘
       │
┌──────▼───────┐
│  Connectors  │ ← Source-specific adapters
└──────┬───────┘
       │
┌──────▼───────┐
│  Scanning    │ ← Multi-threaded scanning
│  Engine      │
└──────┬───────┘
       │
┌──────▼───────┐
│  Detection   │ ← Pattern matching, ML
│  Engine      │
└──────┬───────┘
       │
┌──────▼───────┐
│  Policy      │ ← What to do when found
│  Engine      │
└──────┬───────┘
       │
┌──────▼───────┐
│  Actions     │ ← Block, quarantine, alert
└──────────────┘

Scanning Strategies:
- Real-time (on upload/modification)
- Scheduled batch scans
- Incremental (only changed data)
- Full scans periodically

Actions:
- Alert security team
- Quarantine object
- Block upload/download
- Redact sensitive data
- Remove permissions
- Tag for review

Performance:
- Handle petabytes of data
- Parallel scanning
- Sampling vs full scan
- Resource limits (don't impact production)

False Positives:
- Tunable sensitivity
- Context-aware detection
- Whitelist exceptions
- Human review workflows
```

---

### **Q14. Design Cloud Access Security Broker (CASB)**

**Scope:**
- Monitor and control access to SaaS apps
- 1,000 SaaS applications
- 100,000 employees
- Shadow IT discovery
- DLP, malware detection

**Key Discussion Points:**
```
Deployment Modes:
- API-based (out-of-band)
- Proxy-based (inline, forward/reverse)
- Hybrid approach

Shadow IT Discovery:
- Network traffic analysis
- DNS query analysis
- Cloud provider logs
- Browser extensions

Access Control:
- Conditional access policies
- Device posture checking
- Geo-fencing
- App approval workflows
- OAuth token management

DLP Integration:
- Scan uploads/downloads
- Detect sensitive data
- Block/quarantine files
- Encryption enforcement

Threat Protection:
- Malware scanning
- Anomalous activity detection
- Compromised account detection
- Insider threat detection

Compliance:
- GDPR, HIPAA, PCI-DSS enforcement
- Data residency compliance
- Retention policies
- Audit logging

Use Cases:
- Block upload to personal cloud storage
- Detect ransomware in cloud storage
- Enforce MFA for sensitive apps
- Prevent data sharing with external users
```

---

### **Q15. Design Infrastructure as Code (IaC) Security Scanner**

**Scope:**
- Scan Terraform, CloudFormation, ARM templates
- Pre-deployment validation
- CI/CD integration
- Policy as code

**Key Discussion Points:**
```
Detection Categories:
- Security misconfigurations
- Compliance violations
- Best practice violations
- Cost optimization issues

Specific Checks:
- S3 buckets not public
- Encryption enabled
- Logging enabled
- Network security groups not open
- IAM policies not overly permissive
- Secrets not hardcoded

Architecture:
┌──────────────┐
│  Git Repo    │ (IaC code)
└──────┬───────┘
       │
┌──────▼───────┐
│  Parser      │ ← Parse HCL, JSON, YAML
└──────┬───────┘
       │
┌──────▼───────┐
│  Rule Engine │ ← Check policies
└──────┬───────┘
       │
┌──────▼───────┐
│  Report      │ ← Violations, severity
└──────────────┘

Integration Points:
- Pre-commit hooks
- CI/CD pipeline (block on fail)
- PR comments (GitHub/GitLab)
- IDE plugins
- Policy management portal

Rule Format:
- Declarative (YAML, Rego)
- Imperative (Python scripts)
- Graph queries (for complex relationships)
- Custom rules support

Severity Levels:
- Critical: Deploy blocker
- High: Manual review required
- Medium: Warning
- Low: Informational

Policy as Code:
- Version controlled policies
- Tenant-specific policies
- Exemption management
- Policy testing framework

Remediation:
- Suggested fixes
- Auto-remediation (when safe)
- Terraform plan validation
```

---

### **Q16. Design Cloud Workload Protection Platform (CWPP)**

**Scope:**
- Protect VMs, containers, serverless
- Runtime security monitoring
- Vulnerability management
- File integrity monitoring
- 100,000 workloads

**Key Discussion Points:**
```
Agent Architecture:
- Lightweight agents on workloads
- Kernel-level monitoring
- eBPF for container visibility
- Agentless scanning option

Capabilities:
- Anti-malware
- Host intrusion detection (HIDS)
- File integrity monitoring (FIM)
- Log inspection
- Application control (whitelisting)
- Vulnerability scanning

Container Security:
- Image scanning (pre-deploy, runtime)
- Runtime protection (Falco rules)
- Drift detection (unauthorized changes)
- Network monitoring

Serverless Protection:
- Function scanning
- Runtime protection
- Dependency vulnerabilities
- Invocation anomalies

Threat Detection:
- Behavioral analysis
- Machine learning models
- Known attack patterns
- IOC matching

Central Management:
- Policy distribution
- Agent updates
- Centralized logging
- Compliance reporting

Performance:
- Low overhead (<5% CPU)
- Efficient data collection
- Local analysis vs cloud analysis
- Bandwidth optimization
```

---

## 🔒 **CATEGORY 3: DETECTION & RESPONSE SYSTEMS (7 questions)**

### **Q17. Design Security Information and Event Management (SIEM) System**

**Scope:**
- Ingest 1TB logs/day from 10,000 sources
- Real-time detection
- Historical analysis
- Compliance reporting
- Incident investigation

**Key Discussion Points:**
```
Architecture:
┌──────────────┐
│ Log Sources  │ (Firewalls, servers, apps, cloud)
└──────┬───────┘
       │
┌──────▼───────┐
│  Collectors  │ ← Syslog, agents, APIs
│  /Forwarders │
└──────┬───────┘
       │
┌──────▼───────┐
│  Message     │ ← Kafka, Kinesis
│  Queue       │
└──────┬───────┘
       │
┌──────▼───────┐
│  Parsers/    │ ← Normalize different formats
│  Normalizers │
└──────┬───────┘
       │
┌──────▼───────┐
│  Enrichment  │ ← GeoIP, threat intel
└──────┬───────┘
       │
┌──────▼───────┐
│  Detection   │ ← Real-time rules
│  Engine      │
└──────┬───────┘
       │
┌──────▼───────┐
│  Storage     │ ← Hot (Elasticsearch), Cold (S3)
│  (Tiered)    │
└──────┬───────┘
       │
┌──────▼───────┐
│  Search &    │ ← Investigations, dashboards
│  Analytics   │
└──────────────┘

Log Ingestion:
- Multiple protocols (syslog, HTTP, agents)
- High throughput (millions of events/sec)
- Buffering and backpressure handling
- Duplicate detection

Parsing & Normalization:
- Common schema (ECS, Sigma)
- Field extraction (regex, grok patterns)
- Timestamp normalization
- Data type conversion

Enrichment:
- GeoIP lookup
- DNS resolution
- Threat intelligence feeds
- Asset inventory correlation
- User/entity behavior baseline

Detection Rules:
- Signature-based (Sigma rules)
- Anomaly-based (ML models)
- Behavioral analytics (UEBA)
- Correlation rules (multi-event)

Alerting:
- Severity classification
- Alert deduplication
- Escalation policies
- Integration with ticketing (JIRA, ServiceNow)
- Runbook automation

Investigation:
- Fast search (sub-second on TB of data)
- Timeline visualization
- Entity relationship graphs
- Pivoting across data sources
- Case management

Storage:
- Hot tier (7-30 days, fast search)
- Warm tier (30-90 days, slower)
- Cold tier (>90 days, archive)
- Retention policies (compliance-driven)

Scaling:
- Horizontal scaling (add nodes)
- Index sharding
- Replication for availability
- Query optimization

Compliance:
- Audit trail immutability
- Compliance reports (PCI, SOC2, HIPAA)
- Evidence preservation
- Chain of custody
```

**Expected Depth:**
- Specific detection rule examples
- Storage optimization strategies
- False positive reduction
- Query performance at scale

---

### **Q18. Design Endpoint Detection and Response (EDR) System**

**Scope:**
- 100,000 endpoints (Windows, Mac, Linux)
- Real-time threat detection
- Forensics capabilities
- Automated response
- Offline endpoint support

**Key Discussion Points:**
```
Agent Capabilities:
- Process monitoring (creation, injection)
- File monitoring (creation, modification, deletion)
- Network monitoring (connections, DNS)
- Registry monitoring (Windows)
- User activity monitoring

Data Collection:
- Event streaming vs batching
- Data reduction (filter noise locally)
- Encrypted communication to backend
- Offline queuing
- Bandwidth optimization

Detection Methods:
- Behavioral analysis (process trees, chains)
- Known malware signatures
- YARA rules
- Machine learning models
- IOC matching (file hashes, IPs, domains)

Threat Hunting:
- Query all endpoints (SQL-like)
- File hash search
- Process name search
- Network connection search
- Timeline reconstruction

Response Actions:
- Isolate endpoint from network
- Kill process
- Quarantine file
- Collect forensics data
- Remediate (remove malware)

Forensics:
- Memory dump
- Disk image
- Event logs collection
- Network traffic capture
- Registry snapshots

Central Platform:
- Aggregate data from all agents
- Global threat intelligence
- Cross-endpoint correlation
- Campaign identification

Offline Handling:
- Local detection continues
- Queue data for upload
- Local response actions
- Sync when online

Performance:
- Low CPU/memory footprint
- Kernel-mode driver (Windows)
- eBPF (Linux)
- Minimal impact on user experience

Scale:
- Handle 100K agents reporting
- Real-time analysis
- Historical search
- Agent update distribution
```

---

### **Q19. Design Network Detection and Response (NDR) System**

**Scope:**
- Monitor 10 Gbps network traffic
- East-west and north-south traffic
- Encrypted traffic analysis
- Threat detection without decryption

**Key Discussion Points:**
```
Data Collection:
- Network TAPs vs SPAN ports
- Flow data (NetFlow, IPFIX)
- Full packet capture (selectively)
- Cloud VPC Flow Logs

Traffic Analysis:
- Protocol analysis (HTTP, DNS, TLS, SSH)
- Metadata extraction (without decryption)
- Flow analysis (connection patterns)
- Encrypted traffic fingerprinting

Detection Techniques:
- Anomaly detection (unusual traffic patterns)
- Signature-based (known attack patterns)
- Machine learning (behavioral baselines)
- Threat intelligence correlation

TLS/Encrypted Traffic:
- Certificate analysis
- JA3/JA3S fingerprinting
- SNI inspection
- Traffic volume/timing analysis
- No decryption (privacy preserved)

East-West Detection:
- Lateral movement
- Internal reconnaissance
- Data exfiltration
- Command and control (C2)

Use Cases:
- Detect C2 beaconing
- DNS tunneling
- Data exfiltration
- Malware propagation
- Reconnaissance scanning

Response:
- Alert SOC
- Firewall rule injection
- Network segmentation
- Traffic rerouting
- Packet capture for forensics

Performance:
- Line-rate analysis (10/40/100 Gbps)
- Inline vs passive deployment
- Latency minimization
- Real-time processing

Storage:
Full packets (limited time)
Metadata (longer retention)
Aggregated flows
Tiered storage strategy

## 🔒 **CATEGORY 3: DETECTION & RESPONSE SYSTEMS (continued)**

### **Q20. Design User and Entity Behavior Analytics (UEBA) System** (continued)

**Key Discussion Points (continued):**
```
Machine Learning Models:
- Unsupervised learning (clustering)
- Supervised learning (labeled attacks)
- Time series analysis
- Peer group comparison
- Ensemble methods

Risk Scoring:
- Aggregate multiple weak signals
- Time-decay of old events
- Context-aware scoring
- Dynamic thresholds
- Risk score per user/entity

Architecture:
┌──────────────┐
│ Data Sources │ (Auth, VPN, Files, Email, DB)
└──────┬───────┘
       │
┌──────▼───────┐
│  Data Lake   │ ← Historical data for training
└──────┬───────┘
       │
┌──────▼───────┐
│  Feature     │ ← Extract features (login count,
│  Engineering │   data volume, access patterns)
└──────┬───────┘
       │
┌──────▼───────┐
│  Baseline    │ ← Build normal behavior models
│  Models      │
└──────┬───────┘
       │
┌──────▼───────┐
│  Real-time   │ ← Compare current vs baseline
│  Scoring     │
└──────┬───────┘
       │
┌──────▼───────┐
│  Alert       │ ← Risk score > threshold
│  Generation  │
└──────────────┘

Use Cases:
- Insider threat detection
- Compromised account detection
- Data exfiltration
- Privilege abuse
- Account sharing
- Automated bot detection

Insider Threat Scenarios:
- Employee accessing files before leaving company
- Unusual large file downloads
- Access to resources outside job function
- After-hours database queries
- Copying data to USB/personal cloud

Compromised Account:
- Login from impossible travel
- Sudden change in behavior
- Access from suspicious IP
- Unusual API usage patterns
- Brute force followed by success

Features to Track:
- Login frequency/time/location
- Resources accessed
- Data volume transferred
- Failed access attempts
- Peer group deviation
- Velocity of actions

False Positive Reduction:
- Whitelist legitimate anomalies
- Feedback loop from analysts
- Context awareness (travel, job changes)
- Multi-signal correlation
- Confidence scoring

Investigation Workflow:
- Alert triage
- User timeline reconstruction
- Related entity analysis
- Automated enrichment
- Case management integration

Privacy Considerations:
- GDPR compliance
- Data minimization
- Purpose limitation
- Transparency to employees
- Retention policies
```

**Expected Depth:**
- Specific ML algorithms (Isolation Forest, Autoencoders)
- Feature engineering examples
- Handling concept drift (behavior changes over time)
- Explainability of ML decisions

---

### **Q21. Design Threat Intelligence Platform (TIP)**

**Scope:**
- Aggregate threat intel from 100+ feeds
- 1M+ IOCs (Indicators of Compromise)
- Real-time enrichment
- Share intel with security tools

**Key Discussion Points:**
```
Data Sources:
- Commercial feeds (CrowdStrike, Recorded Future)
- Open source (MISP, AlienVault OTX)
- Internal intel (from incidents)
- ISAC/ISAO sharing communities
- Dark web monitoring

IOC Types:
- IP addresses
- Domain names
- File hashes (MD5, SHA1, SHA256)
- URLs
- Email addresses
- YARA rules
- CVEs

Architecture:
┌──────────────┐
│ Intel Feeds  │ (STIX/TAXII, APIs, manual)
└──────┬───────┘
       │
┌──────▼───────┐
│  Ingestion   │ ← Normalize, deduplicate
│  Pipeline    │
└──────┬───────┘
       │
┌──────▼───────┐
│ Enrichment   │ ← Context, reputation
└──────┬───────┘
       │
┌──────▼───────┐
│   Storage    │ ← Graph DB for relationships
│ (Graph DB)   │
└──────┬───────┘
       │
┌──────▼───────┐
│  Analysis    │ ← Prioritization, scoring
└──────┬───────┘
       │
┌──────▼───────┐
│ Distribution │ ← Push to security tools
└──────────────┘

Data Normalization:
- STIX 2.x format
- Standardized taxonomy
- Confidence scoring
- TLP (Traffic Light Protocol) handling
- Provenance tracking

Enrichment:
- Geolocation
- Autonomous system (AS) info
- Historical reputation
- Related IOCs (pivoting)
- Attribution (threat actor, campaign)
- TTPs (MITRE ATT&CK mapping)

Intelligence Analysis:
- IOC scoring/prioritization
- False positive filtering
- Age decay (old IOCs less relevant)
- Contextual relevance (to your environment)
- Campaign clustering

Integration Points:
- SIEM (enrich alerts)
- Firewall (block IPs/domains)
- Proxy (block URLs)
- EDR (hunt for IOCs)
- Email gateway (block senders)
- DNS firewall

Threat Actor Tracking:
- Actor profiles
- TTPs mapping
- Campaign timelines
- Infrastructure tracking
- Victimology patterns

Sharing:
- STIX/TAXII server
- API for partners
- Community sharing
- Anonymized indicators
- TLP respect

Use Cases:
- Proactive blocking (known bad IPs)
- Alert enrichment (is this IP known malicious?)
- Threat hunting (search for IOCs in environment)
- Incident response (who else is affected?)

Challenges:
- IOC quality (false positives)
- Volume (millions of IOCs)
- Timeliness (fast-moving threats)
- Context (why is this bad?)
- Actionability (can we use this?)

Performance:
- Sub-second IOC lookup
- Handle millions of IOCs
- Real-time feed updates
- Efficient graph queries
```

**Expected Depth:**
- STIX/TAXII protocol understanding
- Graph database choice (Neo4j, JanusGraph)
- IOC scoring methodology
- Integration architecture with other tools

---

### **Q22. Design Security Orchestration, Automation and Response (SOAR) Platform**

**Scope:**
- Automate incident response
- Integrate 50+ security tools
- Playbook execution
- Case management

**Key Discussion Points:**
```
Core Components:
- Case management
- Playbook engine
- Integration framework
- Threat intelligence
- Collaboration tools

Architecture:
┌──────────────┐
│ Alert Sources│ (SIEM, EDR, Email, etc.)
└──────┬───────┘
       │
┌──────▼───────┐
│  Alert       │ ← Deduplication, correlation
│  Aggregation │
└──────┬───────┘
       │
┌──────▼───────┐
│  Playbook    │ ← Automated workflows
│  Engine      │
└──────┬───────┘
       │
┌──────▼───────┐
│ Integration  │ ← Execute actions on tools
│   Layer      │
└──────┬───────┘
       │
┌──────▼───────┐
│     Case     │ ← Track incidents
│  Management  │
└──────────────┘

Playbooks (Example: Phishing):
1. Receive phishing alert from email gateway
2. Extract IOCs (URLs, sender, attachments)
3. Query threat intel for reputation
4. Check if any users clicked link (proxy logs)
5. Isolate affected endpoints (EDR)
6. Block sender domain (email gateway)
7. Create ticket (ServiceNow)
8. Notify SOC analyst
9. Generate incident report

Integration Types:
- API-based (RESTful)
- SSH/CLI commands
- Agent-based
- STIX/TAXII
- Email (IMAP/SMTP)
- Web scraping (when no API)

Actions Supported:
- Query (get alert details, check reputation)
- Contain (isolate endpoint, block IP)
- Remediate (delete email, kill process)
- Enrich (add context, lookup user)
- Notify (send email, Slack, PagerDuty)
- Document (update ticket, log actions)

Decision Points:
- If/then/else logic
- Wait for human approval
- Parallel execution
- Loop constructs
- Error handling

Playbook Categories:
- Phishing response
- Malware outbreak
- DDoS mitigation
- Data breach
- Insider threat
- Vulnerability management

Case Management:
- Track incidents end-to-end
- Assign to analysts
- SLA tracking
- Evidence collection
- Timeline building
- Metrics (MTTR, MTTD)

Human-in-the-Loop:
- Approval steps for sensitive actions
- Analyst decision points
- Escalation workflows
- Manual intervention option

Metrics:
- Incidents automated vs manual
- Time saved
- MTTR reduction
- False positive reduction
- Playbook success rate

Challenges:
- API rate limits
- Tool reliability
- Playbook maintenance
- False positive handling
- Complex decision logic
```

**Expected Depth:**
- Specific tool integrations (Splunk, CrowdStrike, Palo Alto)
- Error handling in playbooks
- Approval workflow design
- Metrics for measuring success

---

### **Q23. Design Deception Technology Platform (Honeypots at Scale)**

**Scope:**
- Deploy 10,000 honeypots/honey tokens
- Detect lateral movement
- Low false positive rate
- Automated deployment

**Key Discussion Points:**
```
Deception Assets:
- Honeypots (fake servers, workstations)
- Honey tokens (fake credentials, files, URLs)
- Honey networks (fake network segments)
- Decoy services (SSH, RDP, SMB, databases)
- Decoy data (fake sensitive files)

Deployment Strategies:
- Breadcrumbs (leave credentials in memory)
- Decoy AD accounts
- Fake file shares
- Fake database entries
- Fake API endpoints
- Fake cloud resources (S3 buckets)

Architecture:
┌──────────────┐
│ Deception    │ (Honeypots, tokens)
│   Assets     │
└──────┬───────┘
       │ (attacker interaction)
┌──────▼───────┐
│  Monitoring  │ ← Log all interactions
│   Sensors    │
└──────┬───────┘
       │
┌──────▼───────┐
│  Analysis    │ ← High-fidelity alerts
│   Engine     │
└──────┬───────┘
       │
┌──────▼───────┐
│  Alert &     │ ← SOC notification
│  Response    │
└──────────────┘

Honeypot Types:
- Low-interaction (emulated services)
- High-interaction (full VMs)
- Hybrid (some services real, some emulated)

Honey Token Examples:
- AWS credentials (fake, monitored)
- Database connection strings
- API keys
- SSH keys
- Browser-saved passwords
- Excel files with "sensitive" data
- Fake customer records

Detection Scenarios:
- Lateral movement (attacker scans network)
- Credential theft (attacker uses decoy creds)
- Data exfiltration (attacker downloads decoy files)
- Reconnaissance (attacker connects to honeypot)

Realism:
- Make decoys believable
- Consistent naming conventions
- Realistic services/data
- Integration with real AD
- Proper network positioning

Alert Fidelity:
- Nearly 100% true positives (no legitimate reason to touch)
- Immediate high-priority alerts
- Automated response (isolate source)
- Forensics collection

Automation:
- Auto-deploy based on network topology
- Adapt to environment changes
- Rotate honey tokens
- Refresh decoy data

Integration:
- AD (create decoy accounts)
- SIEM (send high-priority alerts)
- EDR (isolate attacking endpoint)
- Network (segment attacker)

Attacker Engagement:
- How long to let attacker interact?
- Active deception (mislead attacker)
- Attribution collection
- vs containment (stop immediately)

Challenges:
- Scalability (10K assets)
- Fingerprinting (attacker detects honeypots)
- Maintenance (keep updated)
- Integration with production
```

**Expected Depth:**
- Specific honeypot technologies (Cowrie, Dionaea, T-Pot)
- Honey token implementation details
- Integration with Active Directory
- Anti-fingerprinting techniques

---

## 🌐 **CATEGORY 4: NETWORK & PERIMETER SECURITY (5 questions)**

### **Q24. Design Next-Generation Firewall (NGFW) System**

**Scope:**
- 100 Gbps throughput
- Application-aware filtering
- IPS/IDS integrated
- SSL/TLS inspection
- High availability

**Key Discussion Points:**
```
Architecture:
┌──────────────┐
│   Internet   │
└──────┬───────┘
       │
┌──────▼───────┐
│  NGFW Pair   │ (Active-Active HA)
│   (Inline)   │
└──────┬───────┘
       │
┌──────▼───────┐
│ Internal Net │
└──────────────┘

Packet Processing Pipeline:
1. Packet capture (DPDK, kernel bypass)
2. Session tracking (stateful inspection)
3. Application identification (DPI)
4. Threat detection (IPS signatures)
5. URL filtering
6. SSL decryption (if policy requires)
7. Content inspection (AV, sandboxing)
8. Policy enforcement
9. Logging

Application Identification:
- Deep packet inspection (DPI)
- Behavioral analysis
- Heuristics
- SSL/TLS fingerprinting
- Protocol decoding (HTTP, DNS, TLS)

Security Features:
- Stateful packet filtering
- IPS/IDS (signature + anomaly)
- Anti-malware (stream scanning)
- URL filtering (categories)
- DNS filtering
- Application control
- User identity integration (AD, LDAP)

SSL/TLS Inspection:
- Man-in-the-middle with enterprise CA
- Certificate validation
- Bypass for sensitive apps (banking, health)
- Performance impact considerations
- Privacy concerns

High Availability:
- Active-active or active-passive
- State synchronization
- Session failover
- Health monitoring
- Geographic redundancy

Performance:
- Hardware acceleration (ASIC, FPGA)
- Multi-core packet processing
- Connection tracking at scale
- Minimal latency (<1ms)
- Line-rate throughput

Policy Management:
- Rule ordering (specific to general)
- Object groups (IPs, users, apps)
- Time-based rules
- Geolocation-based rules
- Logging and reporting

Integration:
- SIEM (log forwarding)
- Threat intelligence feeds
- Sandboxing (suspicious files)
- Authentication systems (SAML, RADIUS)

Advanced Threats:
- Zero-day protection (behavioral)
- Encrypted threat detection
- C2 communication blocking
- Botnet detection
- APT prevention

Challenges:
- Encrypted traffic (80%+ of web)
- Performance vs security
- False positives
- Rule complexity
- Vendor lock-in
```

---

### **Q25. Design Zero Trust Network Architecture**

**Scope:**
- 10,000 employees
- Cloud + on-prem resources
- No implicit trust
- Micro-segmentation
- Continuous verification

**Key Discussion Points:**
```
Core Principles:
1. Verify explicitly (never trust, always verify)
2. Least privilege access
3. Assume breach (limit blast radius)

Architecture Components:

┌──────────────┐
│    Users     │ (Employees, contractors, partners)
└──────┬───────┘
       │
┌──────▼───────┐
│  Identity    │ ← Strong AuthN + MFA
│  Provider    │
└──────┬───────┘
       │
┌──────▼───────┐
│ Policy       │ ← Who can access what?
│ Engine       │
└──────┬───────┘
       │
┌──────▼───────┐
│ Zero Trust   │ ← Policy enforcement
│ Gateway      │
└──────┬───────┘
       │
┌──────▼───────┐
│  Resources   │ (Apps, data, services)
└──────────────┘

Identity & Access:
- Strong authentication (MFA mandatory)
- Contextual access (device, location, risk)
- Just-in-time access
- Privileged access management
- Identity-based policies

Device Security:
- Device posture checking
- Compliance verification (AV, patch level)
- Managed vs BYOD
- Device certificates
- EDR agent requirement

Network Segmentation:
- Micro-segmentation (per workload)
- Software-defined perimeter (SDP)
- Application-level isolation
- East-west traffic inspection
- No flat networks

Policy Decision:
- Risk-based decisions
- User + device + location + behavior
- Adaptive policies
- Continuous verification
- Session re-authentication

Policy Enforcement:
- Zero trust gateway/proxy
- Identity-aware proxy
- Service mesh (for microservices)
- Application-level firewalls

Data Security:
- Data classification
- Encryption in transit and at rest
- DLP integration
- Rights management

Monitoring:
- Log all access attempts
- Behavioral analytics
- Anomaly detection
- Continuous risk assessment

Implementation Phases:
1. Identity (strong AuthN/AuthZ)
2. Device (endpoint security, compliance)
3. Network (micro-segmentation)
4. Application (app-level controls)
5. Data (classify, protect)

Use Cases:
- Remote workers (no VPN, direct access)
- Third-party access (contractors, vendors)
- Cloud migration (consistent security)
- Merger & acquisition (separate networks)

Challenges:
- Legacy applications (don't support modern auth)
- User experience (friction)
- Complexity (many components)
- Migration (from perimeter model)
- Cost

Benefits:
- Reduced attack surface
- Limited lateral movement
- Better visibility
- Consistent security (cloud + on-prem)
- Simplified network
```

**Expected Depth:**
- Specific technologies (BeyondCorp, Zscaler, Palo Alto Prisma)
- Policy evaluation logic
- Migration strategy from traditional perimeter
- Handling legacy applications

---

### **Q26. Design Web Application Firewall (WAF) System**

**Scope:**
- Protect 1,000 web applications
- Block OWASP Top 10 attacks
- API protection
- Bot management
- CDN-integrated

**Key Discussion Points:**
```
Deployment Models:
- Cloud-based (Cloudflare, AWS WAF)
- On-premises appliance
- Reverse proxy (ModSecurity)
- CDN-integrated

Architecture:
┌──────────────┐
│    Users     │
└──────┬───────┘
       │
┌──────▼───────┐
│     CDN      │ ← DDoS protection
└──────┬───────┘
       │
┌──────▼───────┐
│     WAF      │ ← Traffic inspection
└──────┬───────┐
       │     (block/allow/challenge)
┌──────▼───────┐
│   Origin     │ (Web servers)
│   Servers    │
└──────────────┘

Protection Categories:

1. OWASP Top 10:
   - SQL injection
   - XSS (reflected, stored, DOM)
   - CSRF
   - XXE
   - SSRF
   - Insecure deserialization
   - Authentication bypass
   - Sensitive data exposure

2. API Protection:
   - Rate limiting per API key
   - Schema validation
   - Input validation
   - Authentication enforcement
   - Parameter tampering

3. Bot Management:
   - Good bots (allow search engines)
   - Bad bots (scrapers, credential stuffing)
   - Bot detection (behavior, fingerprinting)
   - CAPTCHA challenges
   - JavaScript challenges

4. DDoS Mitigation:
   - Layer 7 DDoS
   - Slowloris attacks
   - HTTP floods
   - Connection limits
   - Rate limiting

Detection Methods:
- Signature-based (known attack patterns)
- Anomaly-based (deviation from baseline)
- Behavior-based (suspicious patterns)
- Reputation-based (known bad IPs)

Rule Sets:
- Core rule set (OWASP ModSecurity CRS)
- Application-specific rules
- Custom rules
- Virtual patching (protect unpatched apps)

Actions:
- Block (403 response)
- Challenge (CAPTCHA, JS challenge)
- Rate limit
- Log only (monitor mode)
- Redirect (honeypot)

False Positive Management:
- Tuning period (learning mode)
- Whitelist legitimate patterns
- Per-application tuning
- Confidence scoring
- Feedback loop

Performance:
- Low latency (<5ms)
- High throughput (handle traffic spikes)
- Caching decisions
- Efficient pattern matching

API Security:
- OpenAPI/Swagger validation
- JSON/XML schema enforcement
- Rate limiting per endpoint
- JWT validation
- API key management

Virtual Patching:
- Protect known CVEs without patching app
- Quick deployment
- Buy time for proper patching

Logging & Analytics:
- Blocked requests
- Top attack types
- Top source IPs
- False positive detection
- Compliance reporting

Integration:
- SIEM (send alerts)
- Threat intelligence (update IP blacklists)
- Incident response (automated blocking)
```

**Expected Depth:**
- Specific rule examples (regex patterns)
- False positive handling strategies
- Performance optimization techniques
- Virtual patching use cases

---

### **Q27. Design DDoS Protection System**

**Scope:**
- Protect against 1 Tbps attacks
- Layer 3/4 and Layer 7 DDoS
- Global distribution
- Sub-second mitigation

**Key Discussion Points:**
```
Attack Types:

Layer 3/4 (Network/Transport):
- SYN flood
- UDP flood
- ICMP flood
- DNS amplification
- NTP amplification
- Reflection attacks

Layer 7 (Application):
- HTTP flood (GET/POST)
- Slowloris
- Slow HTTP POST
- SSL/TLS exhaustion
- Application-specific (WordPress XML-RPC)

Architecture (Multi-Layer Defense):

┌──────────────────────────────┐
│  Tier 1: ISP/Transit Scrubbing │ ← Volumetric attacks
│  (BGP blackholing, rate limit) │
└──────────────┬─────────────────┘
               │
┌──────────────▼─────────────────┐
│  Tier 2: Scrubbing Centers      │ ← Traffic diversion
│  (Global PoPs, DPI, filtering)  │
└──────────────┬─────────────────┘
               │
┌──────────────▼─────────────────┐
│  Tier 3: CDN/Edge Protection    │ ← L7 mitigation
│  (WAF, rate limiting, caching)  │
└──────────────┬─────────────────┘
               │
┌──────────────▼─────────────────┐
│  Tier 4: Origin Protection      │ ← Hidden origin
│  (IP whitelisting, VPN, etc.)   │
└────────────────────────────────┘

Detection:
- Traffic baselines (learn normal patterns)
- Anomaly detection (sudden spikes)
- Signature-based (known attack patterns)
- Behavioral analysis
- Entropy analysis (randomness in requests)

Mitigation Techniques:

Network Layer:
- BGP blackhole routing
- Rate limiting
- SYN cookies
- Connection tracking
- Packet filtering (ACLs)
- Scrubbing centers

Application Layer:
- JavaScript challenges
- CAPTCHA
- Rate limiting (per IP, per session)
- Request prioritization (known good users first)
- Content caching (reduce origin load)

Traffic Engineering:
- Anycast routing (distribute load)
- Traffic scrubbing (clean traffic)
- BGP routing manipulation
- GRE tunnels to scrubbing centers

Origin Protection:
- Hide origin IP (behind CDN)
- Whitelist CDN IPs only
- VPN/private connection from CDN to origin
- Rate limiting at origin

Challenges:
- Volumetric attacks (1 Tbps+)
- Amplification attacks (50x-100x)
- Application-layer attacks (look legitimate)
- Encrypted attacks (harder to inspect)
- Low-and-slow attacks (evade detection)

Response Workflow:
1. Detect anomaly (spike in traffic)
2. Analyze pattern (what type of DDoS?)
3. Activate mitigation (appropriate countermeasure)
4. Monitor effectiveness
5. Adjust as attack evolves
6. Document for post-mortem

Legitimate Traffic:
- Prioritize known good users (cookies, auth)
- Challenge unknown users
- Rate limit aggressively during attack
- Queue requests (don't drop immediately)

Global Infrastructure:
- PoPs in major regions
- Anycast IP addressing
- Capacity exceeds largest attacks
- Quick failover

Metrics:
- Baseline traffic vs attack traffic
- Mitigation effectiveness
- False positives (blocked legitimate users)
- Time to detect
- Time to mitigate
```

**Expected Depth:**
- BGP routing manipulation details
- Scrubbing center architecture
- Distinguishing legitimate flash crowds from DDoS
- Handling encrypted DDoS

---

### **Q28. Design Secure Remote Access Solution (VPN Alternative)**

**Scope:**
- 10,000 remote employees
- Zero trust approach
- No VPN (direct access)
- MFA + device compliance
- High availability

**Key Discussion Points:**
```
Traditional VPN Problems:
- Broad network access (lateral movement risk)
- VPN as implicit trust
- Performance bottleneck
- Complex client software
- No application-level control

Modern Approach (Zero Trust Network Access - ZTNA):

Architecture:
┌──────────────┐
│ Remote User  │
└──────┬───────┘
       │ (HTTPS)
┌──────▼───────┐
│  Identity    │ ← Strong AuthN + MFA
│  Provider    │
└──────┬───────┘
       │
┌──────▼───────┐
│ Access Proxy │ ← Policy enforcement
│  (Cloud)     │
└──────┬───────┘
       │ (private connection)
┌──────▼───────┐
│ Connector    │ ← In corporate network
│ (On-prem)    │
└──────┬───────┘
       │
┌──────▼───────┐
│ Applications │
└──────────────┘

Components:

1. Identity Provider:
   - SSO (SAML/OIDC)
   - MFA enforcement
   - Contextual access (device, location, risk)
   - Continuous authentication

2. Device Posture:
   - OS version check
   - Patch level
   - AV/EDR running
   - Disk encryption
   - Certificate-based auth

3. Access Proxy:
   - Application-level gateway
   - No network-level access
   - Per-app policies
   - Session recording
   - Protocol inspection

4. Connector/Agent:
   - Lightweight agent in corporate network
   - Establish outbound connection to cloud
   - No inbound firewall rules needed
   - Relay traffic to internal apps

Access Policies:
- User + device + location + time + risk
- Application-specific (HR app ≠ DevOps tools)
- Least privilege
- Step-up auth for sensitive apps
- Session timeouts

Application Types:
- Web apps (direct proxy)
- SSH/RDP (protocol gateway)
- Databases (SQL proxy)
- File shares (SMB/NFS gateway)
- Custom apps (TCP/UDP tunnel)

User Experience:
- Single sign-on (no repeated logins)
- Browser-based access (no VPN client)
- Fast (no backhauling through VPN concentrator)
- Works from anywhere

Security Benefits:
- No broad network access
- Per-application access control
- Device compliance enforcement
- Visibility into application usage
- Protection against compromised devices

High Availability:
- Global PoPs (multi-region)
- Redundant connectors
- Health monitoring
- Automatic failover
- Split-brain prevention

Monitoring:
- All access logged
- Session recording (for sensitive apps)
- Anomaly detection
- Compliance reporting

Migration Strategy:
- Phase 1: Pilot with IT team
- Phase 2: Web apps
- Phase 3: Legacy apps (SSH, RDP)
- Phase 4: Decommission VPN
```

**Expected Depth:**
- Comparison with traditional VPN
- Policy evaluation logic
- Handling legacy applications
- Split tunneling considerations

---

## 🔐 **CATEGORY 5: DATA PROTECTION & PRIVACY (5 questions)**

### **Q29. Design Data Encryption at Scale**

**Scope:**
- Encrypt data for 100M users
- Data at rest and in transit
- Key management
- Performance requirements
- Compliance (GDPR, HIPAA)

**Key Discussion Points:**
```
Encryption Scope:

1. Data at Rest:
   - Database encryption
   - File system encryption
   - Object storage encryption (S3, Blob)
   - Backup encryption
   - Log encryption

2. Data in Transit:
   - TLS 1.3 (all external traffic)
   - mTLS (internal service-to-service)
   - VPN (site-to-site)
   - HTTPS (web traffic)

Architecture:

┌──────────────┐
│ Application  │
└──────┬───────┘
       │ (encrypt before write)
┌──────▼───────┐
│  Encryption  │ ← Application-layer encryption
│   Library    │
└──────┬───────┘
       │
┌──────▼───────┐
│  Data Store  │ ← Also encrypted at rest
│ (encrypted)  │
└──────────────┘
       │
┌──────▼───────┐
│  Key Mgmt    │ ← KMS (AWS KMS, Azure Key Vault)
│  Service     │
└──────────────┘

Key Management:

Envelope Encryption:
- Data Encryption Key (DEK): Encrypt actual data
- Key Encryption Key (KEK): Encrypt DEKs
- Master Key: In HSM/KMS, encrypts KEKs

Key Hierarchy:
Master Key (HSM)
  └─> KEK per tenant/app
       └─> DEK per data object/row

Key Rotation:
- Automatic rotation (90 days)
- Re-encrypt data with new keys
- Backward compatibility
- Zero downtime rotation

Key Storage:
- HSM for root keys
- KMS for key hierarchy
- Never in application code
- Never in environment variables
- Access via API only

Encryption Methods:

Field-Level Encryption:
- Encrypt sensitive fields only (SSN, CC numbers)
- Searchable encryption (for indexed fields)
- Format-preserving encryption (maintain data type)

Full-Disk Encryption:
- LUKS (Linux), BitLocker (Windows)
- Boot process protection
- Key stored in TPM

Database Encryption:
- Transparent Data Encryption (TDE)
- Column-level encryption
- Application-level encryption (before DB)

Object Storage:
- Server-side encryption (SSE)
- Client-side encryption (encrypt before upload)
- Customer-managed keys

Performance Considerations:
- Hardware acceleration (AES-NI)
- Bulk encryption operations
- Caching decrypted data (carefully)
- Lazy encryption (encrypt on write, not read)

Access Control:
- IAM policies for key access
- Audit all key usage
- Separation of duties (admin ≠ key access)
- Time-bound access

Compliance:
- GDPR (data minimization, encryption)
- HIPAA (PHI encryption required)
- PCI-DSS (cardholder data encryption)
- FIPS 140-2 (cryptographic modules)

Challenges:
- Performance overhead
- Key lifecycle management
- Search on encrypted data
- Analytics on
- encrypted data

Re-encryption at scale
Advanced:

Homomorphic encryption (compute on encrypted data)
Searchable encryption
Order-preserving encryption (dangerous)
Attribute-based encryption


**Expected Depth:**
- Envelope encryption explanation
- Key rotation without downtime
- Performance benchmarks
- Searchable encryption trade-offs

---

### **Q30. Design Privacy-Compliant Data Pipeline (GDPR)**

**Scope:**
- Handle PII for EU users
- GDPR compliance (right to erasure, portability)
- Data minimization
- Consent management
- Cross-border data transfer

**Key Discussion Points:**GDPR Requirements:
Lawful Basis:

Consent (must be specific, informed)
Contract (necessary for service)
Legitimate interest (with balancing test)
Legal obligation



Data Subject Rights:

Right to access (what data do you have?)
Right to rectification (fix incorrect data)
Right to erasure ("right to be forgotten")
Right to portability (export data)
Right to object (stop processing)
Right to restrict processing

<img width="406" height="643" alt="image" src="https://github.com/user-attachments/assets/5da08a37-9f5f-41aa-af3f-2078be1396a7" />


Consent Management:

Granular consent (per purpose)
Consent versioning
Consent audit trail
Easy withdrawal
Proof of consent
Data Minimization:

Collect only necessary data
Purpose limitation (don't reuse without consent)
Retention limits (delete after N days/months)
Anonymization when possible
Data Inventory:

What PII do we have?
Where is it stored? (all systems)
Who has access?
What's the retention period?
Legal basis for processing?
Pseudonymization:

Replace identifiers with pseudonyms
Reversible (with key)
Reduces risk (not full anonymization)
Example: Hash user ID with salt
Anonymization:

Irreversible removal of identifiers
K-anonymity, L-diversity, T-closeness
Differential privacy
For analytics/ML on aggregated data
Right to Erasure Implementation:

Identify all systems with user data
Cascade delete (primary + backups + logs + analytics)
Hard delete vs soft delete
Backup retention (can keep for X days)
Verification (prove it's deleted)
Data Portability:

Export user data in machine-readable format (JSON, CSV)
Include all processed data
Within 30 days of request
Secure delivery
Cross-Border Transfer:

EU to US (Privacy Shield invalidated, use SCCs)
Standard Contractual Clauses (SCCs)
Binding Corporate Rules (BCRs)
Adequacy decisions (EU-approved countries)
Data Processing Agreement (DPA):

With all vendors/processors
Define responsibilities
Sub-processor approval
Audit rights
Breach notification
Privacy by Design:

Default to minimal data collection
Encryption by default
Access controls
Privacy impact assessments (PIAs)
Data protection officer (DPO)
Breach Notification:

Detect breach within hours
Notify DPA within 72 hours
Notify affected users (if high risk)
Document breach details
Technical Implementation:User ID Mapping:

Internal UUID (anonymized)
Map to real identity (encrypted table)
Allows erasure by deleting mapping
Data Catalog:

Metadata about all PII
Automated discovery
Lineage tracking (where data flows)
Compliance tagging
Automation:

Auto-delete after retention period
Auto-anonymize old data
Auto-export for portability requests
Workflow for erasure requests
Challenges:

Distributed data (microservices)
Backups (how to erase from backups?)
Analytics (anonymization vs utility)
Machine learning (models trained on PII)
Third-party systems (can they comply?)


**Expected Depth:**
- Specific GDPR articles referenced
- Anonymization vs pseudonymization techniques
- Handling erasure in distributed systems
- Consent management UX

---
## 🎯 **CATEGORY 6: APPLICATION SECURITY SYSTEMS (continued)**

### **Q31. Design Secure CI/CD Pipeline** (continued)

**Key Discussion Points (continued):**
```
Secrets Management (continued):
- Never in code (git-secrets pre-commit hook)
- Environment-specific secrets
- Secrets injection at runtime (not build time)
- Vault/Secrets Manager integration
- Short-lived credentials (rotate frequently)
- Encrypted in transit and at rest

Specific Tools Integration:

SAST (Static Analysis):
- SonarQube, Checkmarx, Semgrep
- Language-specific analyzers
- Custom rules for internal APIs
- Baseline false positives
- Break build on critical findings

Dependency Scanning:
- Snyk, Dependabot, WhiteSource
- Check against CVE databases
- License compliance (GPL restrictions)
- Transitive dependency analysis
- Auto-create PRs for updates

Container Security:
- Base image selection (minimal, trusted)
- Multi-stage builds (reduce attack surface)
- Image scanning (Trivy, Anchore, Aqua)
- Sign images (Docker Content Trust)
- Scan registry continuously (new CVEs)

IaC Security:
- Terraform: tfsec, Checkov, Terrascan
- CloudFormation: cfn-nag
- Kubernetes: kube-score, Polaris
- Detect misconfigurations before deploy

DAST (Dynamic Analysis):
- OWASP ZAP, Burp Suite
- Run against staging environment
- Authenticated scans
- API security testing
- Time-boxed (don't delay deployments)

Policy Enforcement:
- OPA (Open Policy Agent) for admission control
- Policies as code (versioned in Git)
- Deny privileged containers
- Require resource limits
- Enforce image registry whitelist
- Network policy requirements

Pipeline Security:
- Isolated build environments
- Least privilege for CI/CD service accounts
- Audit all pipeline changes
- Immutable build agents
- Supply chain security (SLSA framework)

Supply Chain Security:
- Verify dependencies (checksums, signatures)
- Use lock files (package-lock.json, Gemfile.lock)
- Private artifact mirrors
- Dependency review process
- SBOM (Software Bill of Materials) generation

Deployment Gates:
- Automated tests pass (unit, integration, security)
- Security scan results reviewed
- Manual approval for production
- Rollback capability
- Blue-green or canary deployments

Monitoring & Feedback:
- Security findings tracked (JIRA integration)
- Metrics dashboard (vulnerabilities over time)
- Developer education (how to fix)
- Fast feedback loop (<10 min for scans)

Challenges:
- Balance security vs velocity
- False positive fatigue
- Tool sprawl (too many security tools)
- Developer friction
- Legacy code (doesn't meet modern standards)

Best Practices:
- Shift left (find issues early)
- Automate everything
- Fail fast (break build on critical issues)
- Educate developers (not just block)
- Continuous improvement (tune tools)
```

**Expected Depth:**
- Specific tool configurations
- How to handle false positives
- Secrets injection mechanisms (Vault integration)
- Supply chain attack prevention

---

### **Q32. Design Vulnerability Management Platform**

**Scope:**
- Track vulnerabilities across 10,000 assets
- Prioritize patching
- SLA tracking
- Integration with scanners
- Risk-based remediation

**Key Discussion Points:**
```
Architecture:

┌──────────────┐
│   Scanners   │ (Nessus, Qualys, OpenVAS, cloud-native)
└──────┬───────┘
       │
┌──────▼───────┐
│  Aggregation │ ← Normalize data from different sources
│   Layer      │
└──────┬───────┘
       │
┌──────▼───────┐
│ Vulnerability│ ← Deduplicate, enrich, correlate
│   Database   │
└──────┬───────┘
       │
┌──────▼───────┐
│ Risk Engine  │ ← Prioritization scoring
└──────┬───────┘
       │
┌──────▼───────┐
│  Workflow    │ ← Assignment, tracking, SLA
│  Management  │
└──────┬───────┘
       │
┌──────▼───────┐
│  Reporting   │ ← Dashboards, compliance reports
└──────────────┘

Data Sources:
- Vulnerability scanners (network, host, web app)
- Cloud security scanners (AWS Inspector, Azure Defender)
- Container scanners (Trivy, Aqua)
- Dependency scanners (Snyk, Dependabot)
- Threat intelligence feeds (exploit availability)
- Asset management systems (CMDB)
- Configuration management databases

Vulnerability Data:
- CVE ID
- CVSS score (v3.1)
- Affected asset
- Severity (Critical, High, Medium, Low)
- Exploit availability (in the wild?)
- Patch availability
- Compensating controls
- First discovered date
- Last seen date

Enrichment:
- Asset criticality (from CMDB)
- Business context (revenue impact)
- Exploit availability (Metasploit, exploit-db)
- Threat actor interest (from threat intel)
- Internet exposure (Shodan, Censys)
- Data sensitivity (PII, financial)

Risk Scoring (Beyond CVSS):
CVSS Base Score (intrinsic vulnerability severity)
+
Environmental Score (our environment)
+
Temporal Score (exploit availability)
+
Asset Criticality (business impact)
+
Threat Intelligence (active exploitation?)
=
Risk Priority Score

Prioritization Framework:
Critical Priority:
- CVSS 9.0+ AND exploited in wild AND internet-facing
- Patch within 24 hours

High Priority:
- CVSS 7.0-8.9 AND public exploit available
- Patch within 7 days

Medium Priority:
- CVSS 4.0-6.9 OR no known exploit
- Patch within 30 days

Low Priority:
- CVSS <4.0 AND internal only
- Patch within 90 days or accept risk

Workflow:
1. Discovery (scanner finds vulnerability)
2. Triage (confirm it's real, not false positive)
3. Assignment (to asset owner / responsible team)
4. Remediation (patch, mitigate, accept risk)
5. Verification (rescan to confirm fixed)
6. Closure (document resolution)

SLA Tracking:
- Time to patch by severity
- Overdue vulnerabilities
- Exceptions/risk acceptances
- Repeat offenders (assets frequently vulnerable)
- Team performance metrics

Remediation Options:
- Patch (preferred)
- Configuration change
- Compensating controls (WAF rule, firewall rule)
- Accept risk (documented decision)
- Remove/decommission asset

Compensating Controls:
- Not internet-facing (firewall blocks)
- WAF rule blocks exploit
- IPS signature deployed
- MFA required (for auth bypass vulns)
- Monitoring increased

Exception Management:
- Justification required
- Time-bound (30/60/90 days)
- Approval workflow (CISO for critical)
- Compensating controls documented
- Regular review

Deduplication:
- Same vulnerability on same asset from multiple scanners
- Merge into single finding
- Track all sources (for verification)

False Positive Handling:
- Mark as false positive
- Require justification
- Track false positive rate per scanner
- Feed back to scanner vendor

Reporting:
- Executive dashboard (high-level metrics)
- Compliance reports (PCI, SOC2, ISO 27001)
- Trend analysis (improving or worsening?)
- Team scorecards
- Asset vulnerability profile

Metrics:
- Mean Time to Detect (MTTD)
- Mean Time to Remediate (MTTR)
- Vulnerability backlog
- SLA compliance %
- Repeat vulnerabilities
- Coverage (% of assets scanned)

Integration:
- Ticketing systems (JIRA, ServiceNow)
- CMDB (asset enrichment)
- SIEM (correlation with attacks)
- Patch management systems
- Change management

Challenges:
- False positives (scanner accuracy)
- Asset discovery (unknown assets)
- Patching legacy systems (can't patch)
- Developer resistance (fix my code?)
- Prioritization (too many critical?)
- Scan frequency vs load

Automation:
- Auto-assign to asset owners
- Auto-close when verified fixed
- Escalate overdue vulnerabilities
- Generate executive summaries
- Trigger patching workflows
```

**Expected Depth:**
- Risk scoring formula beyond CVSS
- Handling unpatchable systems
- Metrics that matter to executives
- Integration with ticketing systems

---

### **Q33. Design Software Composition Analysis (SCA) System**

**Scope:**
- Track open source dependencies
- Vulnerability detection
- License compliance
- 10,000 applications
- Multiple languages (Java, Python, JavaScript, Go)

**Key Discussion Points:**
```
Purpose:
- Identify vulnerable dependencies
- License compliance (avoid GPL in proprietary code)
- Supply chain security
- Outdated dependency detection

Architecture:

┌──────────────┐
│  Developer   │
│  IDE         │ ← IDE plugin (real-time feedback)
└──────┬───────┘
       │
┌──────▼───────┐
│  Source Code │
│  Repository  │
└──────┬───────┘
       │
┌──────▼───────┐
│  CI/CD       │ ← SCA scan on every build
│  Pipeline    │
└──────┬───────┘
       │
┌──────▼───────┐
│  SCA Engine  │ ← Dependency parsing + analysis
└──────┬───────┘
       │
┌──────▼───────┐
│  Vulnerability│ ← CVE database, advisories
│  Database    │
└──────┬───────┘
       │
┌──────▼───────┐
│  Policy      │ ← License rules, version policies
│  Engine      │
└──────┬───────┘
       │
┌──────▼───────┐
│  Dashboard   │ ← Visualization, reporting
└──────────────┘

Dependency Detection:
- Parse manifest files:
  - Java: pom.xml, build.gradle
  - Python: requirements.txt, Pipfile, poetry.lock
  - JavaScript: package.json, package-lock.json
  - Go: go.mod, go.sum
  - Ruby: Gemfile, Gemfile.lock
  - .NET: packages.config, *.csproj

- Build dependency tree (including transitive)
- Identify exact versions
- Detect dev vs production dependencies

Vulnerability Detection:
- Match dependencies against CVE databases
- Check GitHub Security Advisories
- Snyk vulnerability database
- OSS Index, NVD
- Language-specific databases (PyPI, npm)

Direct vs Transitive:
- Direct: Dependencies you explicitly declared
- Transitive: Dependencies of your dependencies
- Transitive are often the problem (harder to track)

Vulnerability Reporting:
- CVE ID
- Severity (CVSS score)
- Affected versions
- Fixed version (upgrade path)
- Exploit availability
- Reachability analysis (is vulnerable code actually used?)

Reachability Analysis:
- Static analysis to determine if vulnerable code path is reachable
- Reduces false positives
- Example: Vulnerable method in library, but you don't call it

License Compliance:
- Identify all licenses (MIT, Apache, GPL, BSD, proprietary)
- License compatibility checking
- Policy enforcement:
  - ✅ Allow: MIT, Apache 2.0, BSD
  - ⚠️ Review: LGPL, MPL
  - ❌ Deny: GPL (copyleft, must open source your code)

License Policies by Context:
- Open source project: GPL okay
- Proprietary SaaS: GPL not okay (copyleft issue)
- Internal tools: More permissive

Supply Chain Security:
- Verify package integrity (checksums)
- Check for typosquatting (similar package names)
- Detect malicious packages
- Monitor package ownership changes
- Dependency confusion attacks

SBOM (Software Bill of Materials):
- Generate SBOM for each application
- Format: SPDX, CycloneDX
- Include all dependencies + versions + licenses
- Share with customers (transparency)
- Required by some regulations (FDA, NTIA)

Remediation:
- Upgrade to fixed version (preferred)
- Patch dependency (risky)
- Remove dependency (if not needed)
- Find alternative package
- Exploit mitigation (if can't upgrade)

Auto-Remediation:
- Dependabot: Auto-create PRs for updates
- Renovate: Similar, more configurable
- Snyk: Fix PRs with context
- Test automatically (ensure not breaking)

Policy Enforcement:
- Block build if critical vulnerability found
- Block build if forbidden license detected
- Require security review for new dependencies
- Enforce minimum versions

Developer Workflow:
1. Developer adds new dependency
2. IDE plugin warns if vulnerable/bad license
3. PR created, SCA scan runs
4. Blocks if critical issues found
5. Security review for new dependencies
6. Merge if approved

Continuous Monitoring:
- New CVEs published daily
- Rescan dependencies regularly (even if code unchanged)
- Alert when dependency becomes vulnerable
- Dependency update notifications

Challenges:
- Transitive dependency explosion (hundreds)
- False positives (vulnerable but unreachable code)
- Update fatigue (constant dependency updates)
- Breaking changes in updates
- Abandoned packages (no longer maintained)

Metrics:
- Known vulnerable dependencies
- Mean time to update
- License compliance %
- Dependency freshness (how outdated?)
- Direct vs transitive vulnerabilities

Advanced Features:
- Private vulnerability database (internal findings)
- Custom license policies per project
- Integration with artifact repositories (Artifactory, Nexus)
- Bill of Materials (BOM) management
```

**Expected Depth:**
- Transitive dependency handling
- Reachability analysis implementation
- License compliance for commercial software
- Handling abandoned packages

---

### **Q34. Design API Security Gateway**

**Scope:**
- Secure 1,000 microservice APIs
- Authentication & authorization
- Rate limiting, DDoS protection
- API analytics
- High throughput (100K req/sec)

**Key Discussion Points:**
```
Architecture:

┌──────────────┐
│   Clients    │ (Mobile, Web, Partners)
└──────┬───────┘
       │ (HTTPS)
┌──────▼───────┐
│  API Gateway │
│   (Ingress)  │
└──────┬───────┘
       │
┌──────▼───────┐
│ Authentication│ ← Validate JWT, API keys
└──────┬───────┘
       │
┌──────▼───────┐
│ Authorization │ ← Check permissions
└──────┬───────┘
       │
┌──────▼───────┐
│ Rate Limiting │ ← Throttle abusive clients
└──────┬───────┘
       │
┌──────▼───────┐
│ Input         │ ← Validate request schema
│ Validation    │
└──────┬───────┘
       │
┌──────▼───────┐
│ Backend       │ ← Route to microservices
│ Services      │
└──────┬───────┘
       │
┌──────▼───────┐
│ Response      │ ← Transform, filter
│ Processing    │
└──────────────┘

Authentication Methods:
- API Keys (simple, for service-to-service)
- JWT (stateless, for user auth)
- OAuth2 (delegated authorization)
- mTLS (certificate-based, high security)
- HMAC signatures (AWS-style)

JWT Validation:
- Verify signature (RS256 or HS256)
- Check expiration (exp claim)
- Validate issuer (iss claim)
- Validate audience (aud claim)
- Check not-before (nbf claim)
- Revocation check (if needed)

Authorization Models:
- RBAC (Role-Based Access Control)
- ABAC (Attribute-Based Access Control)
- PBAC (Policy-Based Access Control)
- Scope-based (OAuth scopes)

Rate Limiting:
- Per API key (1000 req/hour)
- Per IP address (100 req/min)
- Per user (500 req/hour)
- Per endpoint (10000 req/sec global)
- Token bucket or sliding window algorithm

Rate Limit Implementation:
- Distributed rate limiting (Redis)
- Fixed window vs sliding window
- Burst allowance
- Rate limit headers (X-RateLimit-Remaining)
- 429 response when exceeded

Input Validation:
- JSON schema validation
- OpenAPI/Swagger spec enforcement
- Parameter type checking
- String length limits
- Regex pattern matching
- SQL injection prevention
- XSS prevention

Security Features:
- WAF integration (OWASP Top 10)
- DDoS protection (challenge suspicious requests)
- Bot detection (challenge/CAPTCHA)
- Request signing (prevent tampering)
- Response filtering (don't leak internal errors)

Request Transformation:
- Add headers (correlation ID, auth context)
- Remove headers (internal details)
- Body transformation (format conversion)
- Protocol translation (REST to gRPC)

Routing:
- Path-based routing (/users → user-service)
- Header-based routing (version, region)
- Weighted routing (canary, A/B testing)
- Circuit breaker (stop routing to failing service)
- Retry logic (idempotent requests)

API Analytics:
- Request/response logging
- Latency tracking (p50, p95, p99)
- Error rate monitoring
- Top consumers
- Most called endpoints
- Geographic distribution

Threat Detection:
- Credential stuffing detection
- Brute force attempts (login endpoints)
- Scraping detection (too many reads)
- Anomalous request patterns
- Unusual payload sizes

API Versioning:
- URL-based (/v1/users, /v2/users)
- Header-based (Accept: application/vnd.api+json; version=2)
- Deprecation warnings
- Sunset headers (when will v1 EOL?)

CORS Handling:
- Whitelist allowed origins
- Preflight request handling (OPTIONS)
- Credentials handling
- Exposed headers

WebSocket Security:
- Authentication on upgrade
- Rate limiting per connection
- Message validation
- Connection limits per user

GraphQL Security:
- Query depth limiting (prevent complex queries)
- Query cost analysis
- Persistent query whitelisting
- Introspection disabling (in production)

Performance:
- Connection pooling to backends
- Response caching (Redis)
- HTTP/2, HTTP/3 support
- Compression (gzip, brotli)
- Keep-alive connections

High Availability:
- Multi-region deployment
- Load balancing
- Health checks
- Auto-scaling
- Zero-downtime deployments

API Documentation:
- OpenAPI/Swagger spec
- Authentication guide
- Rate limit documentation
- Error code reference
- Example requests/responses

Monitoring:
- Request throughput
- Error rates (4xx, 5xx)
- Latency (by endpoint)
- Authentication failures
- Rate limit hits
- Backend health

Compliance:
- Audit logging (who called what, when)
- PCI-DSS compliance (if handling payments)
- GDPR compliance (data access logs)
- Data residency (route by region)
```

**Expected Depth:**
- JWT validation implementation details
- Distributed rate limiting (Redis-based)
- Circuit breaker patterns
- GraphQL-specific security concerns

---

### **Q35. Design Code Review & SAST Integration System**

**Scope:**
- Automate security code review
- 1,000 developers, 100 repos
- Pull request integration
- False positive management
- Developer education

**Key Discussion Points:**
```
Architecture:

┌──────────────┐
│  Developer   │
└──────┬───────┘
       │ (creates PR)
┌──────▼───────┐
│  GitHub/     │
│  GitLab      │
└──────┬───────┘
       │ (webhook)
┌──────▼───────┐
│  Automation  │ ← Trigger scans
│  Server      │
└──────┬───────┘
       │
┌──────▼───────┐
│  SAST Tools  │ ← Multiple scanners
│ (Semgrep,    │
│  SonarQube)  │
└──────┬───────┘
       │
┌──────▼───────┐
│  Result      │ ← Normalize, deduplicate
│  Aggregator  │
└──────┬───────┘
       │
┌──────▼───────┐
│  Triage      │ ← Filter false positives
│  Engine      │
└──────┬───────┘
       │
┌──────▼───────┐
│  PR Comment  │ ← Inline feedback
│  Bot         │
└──────────────┘

SAST Tools:
- Semgrep (fast, customizable)
- SonarQube (comprehensive, many languages)
- CodeQL (GitHub native, powerful queries)
- Checkmarx (commercial, deep analysis)
- Bandit (Python-specific)
- Brakeman (Rails-specific)
- ESLint security plugins (JavaScript)

Multi-Tool Strategy:
- Fast tools (Semgrep) for every PR
- Deep tools (CodeQL) for main branch
- Language-specific tools where needed
- Custom rules for internal APIs

Scan Triggers:
- On every pull request (fast feedback)
- On merge to main (comprehensive)
- Scheduled full scans (catch new rules)
- Manual trigger (for investigation)

Finding Types:
- SQL Injection
- XSS (Cross-Site Scripting)
- CSRF
- Path Traversal
- Command Injection
- Hardcoded secrets
- Insecure crypto (MD5, weak random)
- Authentication bypass
- Authorization bugs
- Information disclosure

Severity Classification:
- Critical: Exploitable remotely, high impact
- High: Likely exploitable, significant impact
- Medium: Harder to exploit, or lower impact
- Low: Requires unlikely conditions
- Info: Best practice violation

False Positive Management:
- Baseline scan (mark existing as accepted)
- Suppress with justification
- Suppress with expiration (review in 90 days)
- Pattern-based suppression (this pattern always FP)
- Track suppression rate (tune rules)

Developer Workflow:
1. Developer creates PR
2. Bot comments "Security scan running..."
3. SAST completes in 2-5 minutes
4. Bot comments with findings (inline)
5. Critical findings block merge
6. Developer fixes or justifies
7. Re-scan on new commits
8. Approved when clean

Inline Comments:
- Show finding at exact line of code
- Explain vulnerability
- Show example exploit
- Suggest remediation
- Link to documentation

Example Comment:
```
⚠️ SQL Injection vulnerability detected

Line 42: `query = "SELECT * FROM users WHERE id=" + user_id`

This allows an attacker to inject malicious SQL:
http://example.com/user?id=1%20OR%201=1

Remediation: Use parameterized queries
```python
query = "SELECT * FROM users WHERE id=?"
cursor.execute(query, (user_id,))
```

Learn more: https://example.com/docs/sql-injection
```

Custom Rules:
- Internal API misuse
- Deprecated function usage
- Missing authentication checks
- Insecure configuration
- Company-specific patterns

Rule Development:
- Security team writes rules
- Test against known vulnerabilities
- Measure false positive rate
- Iterate based on feedback
- Version control rules

Integration with IDE:
- Plugin for VS Code, IntelliJ
- Real-time linting (as you type)
- Pre-commit hooks (catch before push)
- Fix suggestions (auto-fix where possible)

Security Champions:
- Train developers in secure coding
- Champions review security findings
- Reduce burden on security team
- Educate peers

Metrics:
- Findings introduced (per PR, per developer)
- Findings fixed (MTTR)
- False positive rate
- Coverage (% of code scanned)
- High-severity findings
- Repeat violations (same pattern)

Gamification:
- Leaderboard (most secure code)
- Badges (security champion, zero vulns)
- Rewards for finding real issues

Compliance:
- Track security reviews per PR
- Audit trail (who approved what)
- Compliance reports (PCI, SOC2)
- Evidence for auditors

Advanced Features:
- Dataflow analysis (track tainted data)
- AI-powered triage (ML to predict FPs)
- Auto-fix suggestions
- Interactive fix guidance

Challenges:
- Scan performance (too slow = ignored)
- False positive fatigue
- Developer friction
- Legacy code (too many findings)
- Rule maintenance
```

**Expected Depth:**
- Specific SAST tool comparisons
- False positive reduction techniques
- Developer adoption strategies
- Custom rule examples

---

## 🔐 **CATEGORY 7: ADVANCED SECURITY SYSTEMS (5 questions)**

### **Q36. Design Security Data Lake**

**Scope:**
- Centralize all security data (logs, alerts, threats)
- Petabyte scale
- Real-time and historical analysis
- ML/AI for threat detection
- Data retention (7 years for compliance)

**Key Discussion Points:**
```
Architecture:

┌──────────────────────────────────────┐
│        Data Sources                  │
│  (SIEM, EDR, Firewall, Cloud, etc.) │
└───────────────┬──────────────────────┘
                │
┌───────────────▼──────────────────────┐
│        Ingestion Layer               │
│  (Kafka, Kinesis, Fluentd)          │
│  - Schema validation                 │
│  - Data enrichment                   │
│  - Routing                           │
└───────────────┬──────────────────────┘
                │
┌───────────────▼──────────────────────┐
│        Storage Layer                 │
│  Hot: Elasticsearch (7-30 days)     │
│  Warm: S3/ADLS (30 days - 1 year)   │
│  Cold: Glacier (1-7 years)          │
└───────────────┬──────────────────────┘
                │
┌───────────────▼──────────────────────┐
│        Processing Layer              │
│  - Stream processing (Flink, Spark) │
│  - Batch processing (Spark)         │
│  - ML pipelines                      │
└───────────────┬──────────────────────┘
                │
┌───────────────▼──────────────────────┐
│        Analytics Layer               │
│  - SQL queries (Athena, Presto)     │
│  - Threat hunting                    │
│  - Dashboards (Kibana, Grafana)     │
│  - ML models                         │
└──────────────────────────────────────┘

Data Sources:
- SIEM logs (alerts, events)
- EDR telemetry (process, network, file)
- Network flows (NetFlow, VPC Flow)
- Cloud logs (CloudTrail, Activity Logs)
- Firewall logs
- Proxy logs
- DNS logs
- Threat intelligence feeds
- Vulnerability scan results
- Asset inventory

Data Ingestion:
- High throughput (millions of events/sec)
- Backpressure handling
- Schema evolution
- Data validation
- Duplicate detection
- Enrichment (GeoIP, DNS, asset info)

Storage Strategy:
Hot Tier (0-30 days):
- Fast search (sub-second)
- Elasticsearch or OpenSearch
- Expensive storage
- Recent incidents, active investigations

Warm Tier (30 days - 1 year):
- Slower search (seconds)
- Object storage (S3, ADLS, GCS)
- Parquet format (compressed, columnar)
- SQL queries via Athena/Presto

Cold Tier (1-7 years):
- Archive (minutes to hours to retrieve)
- Glacier, Archive storage
- Compliance retention
- Rarely accessed

Data Schema:
- Common schema (ECS, OCSF)
- Normalized fields (timestamp, source_ip, user)
- Metadata (source, ingestion_time, enrichment)
- Raw data (original log)

Use Cases:

1. Threat Hunting:
   - Interactive queries across all data
   - Pivot from one entity to another
   - Historical analysis
   - Hypothesis testing

2. Incident Investigation:
   - Timeline reconstruction
   - Related entity search
   - Full context retrieval

3. Machine Learning:
   - Anomaly detection models
   - User behavior modeling
   - Threat classification
   - Predictive analytics

4. Compliance:
   - Audit log retention
   - Report generation
   - Evidence preservation
   - Chain of custody

5. Security Metrics:
   - KPIs and dashboards
   - Trend analysis
   - Benchmarking

Real-Time Processing:
- Stream analytics (Flink, Spark Streaming)
- Correlation rules
- Real-time alerting
- Aggregation (counts, sums, stats)

Batch Processing:
- Daily/weekly aggregations
- ML model training
- Report generation
- Data quality checks

Data Governance:
- Data classification (PII, sensitive)
- Access controls (RBAC)
- Data masking (for analysts)
- Audit logging (who accessed what)
- Data lineage tracking

Query Performance:
- Partitioning (by date, source)
- Indexing strategy
- Compression (Parquet, ORC)
- Caching hot queries
- Query optimization

Security:
- Encryption at rest (all tiers)
- Encryption in transit (TLS)
- Key management (KMS)
- Access logging
- Network isolation

Cost Optimization:
- Tiered storage (hot/warm/cold)
- Data lifecycle policies
- Compression
- Sampling (for analytics)
- Query cost limits

Data Retention:
- Policy-driven (by data type)
- Compliance requirements (7 years financial, 1 year access logs)
- Automatic archival
- Automatic deletion (GDPR right to erasure)

Challenges:
- Scale (petabytes)
- Cost (storage + compute)
- Performance (fast queries on huge data)
- Data quality (garbage in, garbage out)
- Schema evolution (changing log formats)
```

**Expected Depth:**
- Storage tier trade-offs
- Query optimization at scale
- Cost management strategies
- ML pipeline architecture

---

### **Q37. Design Insider Threat Detection System**

**Scope:**
- Monitor 10,000 employees
- Detect malicious insiders
- Privacy-preserving
- Behavioral analytics
- Investigation workflow

**Key Discussion Points:**
```
Threat Scenarios:
- Data exfiltration (steal customer data)
- Intellectual property theft
- Sabotage (delete systems)
- Fraud (financial manipulation)
- Espionage (sell secrets to competitors)

Data Sources:
- Authentication logs (logins, failures)
- VPN access logs
- File access logs (read, copy, delete)
- Email logs (to/from, attachments)
- Database query logs
- Cloud API calls (S3 downloads, etc.)
- USB device usage
- Print logs
- Badge access (physical entry/exit)
- HR data (performance, termination)

Architecture:

┌──────────────┐
│ Data Sources │
└──────┬───────┘
       │
┌──────▼───────┐
│ Data Lake    │ ← Store all activity
└──────┬───────┘
       │
┌──────▼───────┐
│ Baseline     │ ← Learn normal behavior
│ Engine       │
└──────┬───────┘
       │
┌──────▼───────┐
│ Anomaly      │ ← Detect deviations
│ Detection    │
└──────┬───────┘
       │
┌──────▼───────┐
│ Risk Scoring │ ← Aggregate weak signals
└──────┬───────┘
       │
┌──────▼───────┐
│ Investigation│ ← Case management
│ Workflow     │
└──────────────┘

Behavioral Baselines:
- Typical work hours (9am-5pm)
- Typical locations (office, home)
- Typical file access (job-related)
- Typical data volume (downloads
Peer group comparison (similar roles)

Anomalies to Detect:

Access after termination notice
Large data downloads (unusual volume)
Access to unrelated systems (HR accessing source code)
After-hours activity (2am database queries)
Geo-impossible travel (login from US, then China 1 hour later)
USB usage (policy violation)
Printing sensitive documents
Emailing to personal accounts
Cloud uploads to personal storage

Risk Indicators:

Recent performance review (negative)
Resignation submitted
Financial stress (from background check)
Access to valuable IP
Disgruntled (complaints, disciplinary action)
Short tenure (new employees higher risk)
Excessive access (more privileges than needed)

Risk Scoring Model:
Base Risk (role, access level)
+
Behavioral Anomalies (multiple weak signals)
+
Contextual Factors (recent termination)
+
Historical Patterns (previous violations)
Current Risk Score (0-100)
Example:

Employee: Alice (Software Engineer)
Base risk: 30 (has access to source code)
Anomalies detected:

Logged in at 3am (unusual time): +10
Downloaded 10GB source code (10x normal): +20
Uploaded to personal Dropbox: +30
Resignation submitted last week: +20


Total risk score: 110 (HIGH RISK)
Action: Alert security team immediately

Investigation Workflow:

Anomaly detected → Risk score calculated
If score > threshold → Create case
Assign to insider threat analyst
Gather context (HR, manager input)
Review activity timeline
Determine if malicious or benign
If malicious → involve legal, HR, law enforcement
If benign → close case, update baseline

Privacy Considerations:

GDPR compliance (legitimate interest)
Minimize data collection
Access controls (limited analysts)
Purpose limitation (security only)
Employee notification (monitoring policy)
Anonymization where possible
Audit all access to employee data

False Positive Reduction:

Context awareness (business travel explains unusual location)
Whitelisting (legitimate bulk downloads)
Peer comparison (everyone in team working late)
Feedback loop (analyst marks FP, system learns)

Integration:

HR system (terminations, performance)
Physical security (badge access)
IT helpdesk (tickets)
Legal (hold data for investigations)

Automated Response:

High risk: Disable account immediately
Medium risk: Require MFA re-auth
Low risk: Alert only, no action

Metrics:

True positives (actual insider threats caught)
False positives (benign activity flagged)
Time to detect (incident to alert)
Time to investigate (alert to resolution)

Challenges:

Privacy concerns (employee monitoring)
False positives (legitimate unusual activity)
Sophisticated insiders (know how to evade)
Scale (10K employees = lots of data)
Proving intent (malicious vs mistake)


**Expected Depth:**
- Specific ML models (Isolation Forest, LSTM)
- Privacy-preserving techniques
- Legal/HR coordination process
- Handling false positives

```
## 🔐 **CATEGORY 7: ADVANCED SECURITY SYSTEMS (continued)**

### **Q38. Design Supply Chain Security Platform**

**Scope:**
- Secure software supply chain
- Vendor risk management
- Third-party code verification
- Build provenance tracking
- SBOM management

**Key Discussion Points:**
```
Supply Chain Threats:
- Compromised dependencies (malicious packages)
- Typosquatting (similar package names)
- Dependency confusion (internal vs public)
- Compromised build systems
- Malicious contributors
- Update hijacking (package ownership transfer)
- Backdoored compilers (Reflections on Trusting Trust)

Architecture:

┌──────────────┐
│  Developers  │
└──────┬───────┘
       │
┌──────▼───────┐
│ Dependency   │ ← Approved dependencies only
│ Firewall     │
└──────┬───────┘
       │
┌──────▼───────┐
│ Build System │ ← Signed, attested builds
│ (Isolated)   │
└──────┬───────┘
       │
┌──────▼───────┐
│ Artifact     │ ← Signed artifacts + SBOM
│ Repository   │
└──────┬───────┘
       │
┌──────▼───────┐
│ Verification │ ← Check signatures, SBOM
│ & Deployment │
└──────────────┘
```
Dependency Management:

Private Registry/Proxy:
- All packages flow through internal registry
- Mirror approved public packages
- Block direct access to public registries
- Virus/malware scanning
- License checking
- Vulnerability scanning before approval

Dependency Approval Workflow:
1. Developer requests new dependency
2. Automated scanning (vulnerabilities, license)
3. Security review (if high risk)
4. Manual testing
5. Approve and cache in private registry
6. Monitor for new vulnerabilities

Dependency Confusion Prevention:
- Namespace prefixing (internal packages)
- Prioritize internal registry over public
- Explicit scoping (@company/package-name)
- Block ambiguous names

Typosquatting Detection:
- Check against known package names
- Levenshtein distance analysis
- Warn on similar names
- Blocklist known typosquats

Build Provenance (SLSA Framework):

Level 1: Documentation
- Document build process
- SBOM generation

Level 2: Hosted Build Service
- Use trusted CI/CD
- Version controlled build scripts
- Automated builds

Level 3: Hardened Builds
- Isolated build environments
- Provenance attestation
- Non-falsifiable provenance

Level 4: Hermetic Builds
- Fully reproducible builds
- Two-party review
- All dependencies declared

Build Attestation:
- Cryptographically signed metadata
- Who built it (build system identity)
- When (timestamp)
- What (source commit hash)
- How (build parameters)
- Dependencies used (exact versions + hashes)

In-Toto Framework:
- Define supply chain layout (steps + roles)
- Each step produces signed metadata
- Verify entire chain before deployment
- Detect unauthorized steps

SBOM (Software Bill of Materials):

Components:
- All dependencies (direct + transitive)
- Component name, version, supplier
- Relationships (depends on, contains)
- Licenses
- Cryptographic hashes
- Security vulnerabilities (CVEs)

Formats:
- SPDX (Linux Foundation)
- CycloneDX (OWASP)
- SWID (ISO/IEC 19770-2)

Use Cases:
- Vulnerability management (what's affected?)
- License compliance
- Incident response (is component X in production?)
- Supply chain transparency
- Regulatory compliance (FDA, NTIA)

SBOM Management:
- Generate at build time
- Store with artifacts
- Version control
- Diff between versions
- Search/query capability
- Alert on new vulnerabilities

Artifact Signing:

Container Images:
- Docker Content Trust (Notary)
- Cosign (Sigstore)
- Sign image digests (not tags)
- Admission controller verifies

Binary Artifacts:
- GPG signatures
- Code signing certificates
- Timestamp signatures (prove when)

Package Signing:
- npm packages (npm signature)
- PyPI (PGP signatures)
- Maven (GPG signatures)

Verification at Deployment:
- Check signature before deploy
- Verify signature chain
- Check revocation lists
- Enforce policy (only signed allowed)

Vendor Risk Management:

Vendor Assessment:
- Security questionnaire
- SOC 2 report review
- Penetration test results
- Incident history
- Access requirements
- Data handling practices

Third-Party Access:
- Least privilege
- Time-bound access
- MFA required
- Audit logging
- Separate environments (no prod access)

Continuous Monitoring:
- Monitor vendor security posture
- Track vulnerabilities in vendor products
- Review vendor incidents
- Annual reassessment

SaaS Security:
- OAuth scopes (minimal)
- API key rotation
- Data encryption
- Access logs review
- Offboarding process

Monitoring & Detection:

Package Monitoring:
- Monitor npm, PyPI, Maven for malicious packages
- Automated takedown requests
- Internal blocklist updates

Dependency Updates:
- Monitor for new versions
- Security advisories
- Breaking changes
- Automated update PRs (Dependabot)

Build Integrity:
- Detect modified build scripts
- Unauthorized build steps
- Unexpected dependencies
- Modified source code

Incident Response:

Compromised Dependency:
1. Identify affected applications (SBOM search)
2. Assess exposure (is vulnerable code used?)
3. Patch or remove dependency
4. Redeploy affected services
5. Investigate if exploited
6. Notify customers if needed

Compromised Build:
1. Revoke compromised artifacts
2. Rebuild from clean source
3. Investigate compromise vector
4. Update build security
5. Verify no backdoors deployed

Metrics:
- Time to detect supply chain compromise
- % dependencies with SBOM
- % signed artifacts
- Unapproved dependency usage
- Vendor risk scores

Challenges:
- Developer friction (slower to add deps)
- Transitive dependencies (hundreds)
- False positives (legitimate new packages)
- Reproducible builds (hard to achieve)
- Legacy systems (can't easily change)


**Expected Depth:**
- SLSA levels explained
- In-toto vs Sigstore differences
- Dependency confusion attack details
- SBOM generation and management

---

### **Q39. Design Security Chaos Engineering Platform**

**Scope:**
- Test security controls in production
- Automated attack simulations
- Continuous validation
- Resilience testing
- Safe failure injection

**Key Discussion Points:**
```
Concept:
- Proactively test security defenses
- Inject realistic attacks in controlled manner
- Verify detection and response
- Build resilience through practice
- "Break things on purpose before attackers do"

Architecture:

┌──────────────┐
│  Attack      │ ← Define scenarios
│  Scenarios   │
└──────┬───────┘
       │
┌──────▼───────┐
│  Scheduler   │ ← When to run tests
└──────┬───────┘
       │
┌──────▼───────┐
│  Execution   │ ← Run attacks safely
│  Engine      │
└──────┬───────┘
       │
┌──────▼───────┐
│  Monitoring  │ ← Did we detect it?
└──────┬───────┘
       │
┌──────▼───────┐
│  Validation  │ ← Pass/fail criteria
└──────┬───────┘
       │
┌──────▼───────┐
│  Reporting   │ ← Gaps, improvements
└──────────────┘
```
Attack Scenarios:

Network Attacks:
- Port scanning (should be detected by IDS)
- DDoS simulation (rate limiting working?)
- Lateral movement attempts (segmentation effective?)
- Unusual outbound connections (C2 beaconing)

Application Attacks:
- SQL injection attempts (WAF blocking?)
- XSS attempts (CSP working?)
- Authentication brute force (rate limiting?)
- API abuse (throttling effective?)

Credential Attacks:
- Compromised credential simulation (detection working?)
- Privilege escalation attempts (monitoring?)
- Unusual access patterns (UEBA alerting?)

Data Exfiltration:
- Large data downloads (DLP detecting?)
- Upload to external storage (blocked?)
- DNS tunneling (detected?)

Insider Threat:
- After-hours access simulation
- Bulk data access
- Unusual application usage

Infrastructure:
- Unpatched vulnerability exploitation
- Misconfiguration exploitation
- Container escape attempts

Execution Engine:

Safe Execution:
- Test environment first (never start in prod)
- Gradual rollout (one system, then more)
- Kill switch (abort immediately if issues)
- Scope limiting (specific targets only)
- Time limiting (run for 5 minutes max)
- Rate limiting (don't overwhelm systems)

Blast Radius Control:
- Isolated test accounts (not real users)
- Synthetic data (not production data)
- Read-only operations (when possible)
- Reversible actions (can undo)
- Monitoring during execution

Attack Techniques:

Red Team Automation:
- Automated reconnaissance (nmap, subdomain enum)
- Vulnerability scanning (Nessus, OpenVAS)
- Exploitation (Metasploit modules)
- Post-exploitation (credential dumping, lateral movement)
- Data exfiltration simulation

Breach and Attack Simulation (BAS):
- Commercial tools (SafeBreach, Cymulate, AttackIQ)
- Pre-built attack scenarios
- Continuous testing
- Compliance validation (MITRE ATT&CK coverage)

Purple Team Exercises:
- Red team attacks + Blue team detection
- Collaborative improvement
- Gap identification
- Playbook validation

Detection Validation:

Expected Outcomes:
- SIEM alert triggered
- EDR blocks or alerts
- SOC ticket created
- Automated response executed
- Incident responder notified

Pass/Fail Criteria:
- Pass: Detected within SLA (5 minutes)
- Pass: Correct severity assigned
- Pass: Response executed
- Fail: No detection
- Fail: Detected but too slow
- Fail: False negative

Continuous Testing:
- Daily: Simple attacks (port scan)
- Weekly: Complex attacks (lateral movement)
- Monthly: Full kill chain simulation
- Quarterly: Red team exercise

Use Cases:

1. Detection Gap Identification:
   - Run attack scenarios
   - Find what's NOT detected
   - Prioritize detection engineering
   - Build new rules

2. Control Validation:
   - Test WAF rules (do they block?)
   - Test firewall rules (do they work?)
   - Test DLP policies (catching data leaks?)
   - Test MFA (can't bypass?)

3. Response Validation:
   - Test incident response playbooks
   - Verify automation works
   - Check escalation paths
   - Measure response time (MTTR)

4. Training:
   - SOC analyst training
   - Incident responder practice
   - New tool familiarization
   - Muscle memory building

5. Compliance:
   - Prove controls work (auditors love this)
   - MITRE ATT&CK coverage validation
   - Regulatory requirements (PCI DSS testing)

MITRE ATT&CK Integration:
- Map scenarios to tactics/techniques
- Coverage heatmap (tested vs not tested)
- Prioritize untested techniques
- Track coverage over time

Reporting:

Real-Time:
- Test in progress dashboard
- Pass/fail indicators
- Detection timeline
- Response actions taken

Summary Reports:
- Tests run (count, frequency)
- Success rate (detected %)
- Mean time to detect (MTTD)
- Mean time to respond (MTTR)
- Gaps identified
- Improvements recommended

Trend Analysis:
- Detection coverage improving?
- Response time decreasing?
- New gaps emerging?
- Control effectiveness

Safety Measures:

Pre-Flight Checks:
- Verify test environment healthy
- Verify monitoring is working
- Notify SOC (expected test activity)
- Backup critical systems
- Have rollback plan

During Execution:
- Monitor for unexpected impact
- Watch for cascading failures
- Check blast radius (contained?)
- Ready to abort

Post-Execution:
- Clean up test artifacts
- Verify no persistence (backdoors left)
- Document lessons learned
- Update detection rules

Risk Management:
- Risk assessment per scenario
- Approval required for high-risk
- Insurance/liability considerations
- Incident response plan if goes wrong

Challenges:
- False positives (alert fatigue from testing)
- Production impact (tests cause outages)
- Scope creep (tests too aggressive)
- Compliance issues (testing in prod)
- Coordinating with teams

Best Practices:
- Start small (low-risk tests first)
- Automate incrementally
- Coordinate with teams
- Document everything
- Learn from failures
- Continuous improvement
```

**Expected Depth:**
- Specific BAS tools and capabilities
- MITRE ATT&CK mapping strategy
- Safety mechanisms in detail
- Metrics for measuring effectiveness

```

### **Q40. Design Security Operations Center (SOC) Platform**

**Scope:**
- 24/7 security monitoring
- Alert triage and investigation
- Incident response orchestration
- Threat intelligence integration
- 100K alerts/day, 50 analysts

**Key Discussion Points:**
```
Architecture:

┌──────────────────────────────────┐
│      Detection Sources           │
│  (SIEM, EDR, IDS, WAF, Cloud)   │
└────────────┬─────────────────────┘
             │
┌────────────▼─────────────────────┐
│      Alert Aggregation           │
│  - Deduplication                 │
│  - Normalization                 │
│  - Enrichment                    │
└────────────┬─────────────────────┘
             │
┌────────────▼─────────────────────┐
│      Triage & Prioritization     │
│  - ML-based scoring              │
│  - Context enrichment            │
│  - Auto-close false positives    │
└────────────┬─────────────────────┘
             │
┌────────────▼─────────────────────┐
│      Case Management             │
│  - Analyst assignment            │
│  - Investigation workflow        │
│  - Collaboration                 │
└────────────┬─────────────────────┘
             │
┌────────────▼─────────────────────┐
│      Response Orchestration      │
│  (SOAR) - Automated playbooks    │
└────────────┬─────────────────────┘
             │
┌────────────▼─────────────────────┐
│      Metrics & Reporting         │
└──────────────────────────────────┘
```
Alert Management:

Alert Volume Problem:
- 100K alerts/day = 1.15 alerts/second
- 99% may be false positives
- Analyst burnout from noise
- Real threats buried in noise

Deduplication:
- Group similar alerts (same source, same type)
- Time-based grouping (burst of alerts = one incident)
- Entity-based (all alerts for user Alice → one case)
- Reduces 100K alerts → 1K incidents

Normalization:
- Common schema across sources
- Consistent field names (source_ip, dest_ip)
- Standardized severity (Critical/High/Medium/Low)
- Unified timestamps (UTC)

Enrichment:
- Threat intelligence (is this IP malicious?)
- Asset context (is this a critical server?)
- User context (is this a privileged user?)
- Historical context (seen this before?)
- GeoIP (where is this IP located?)

Triage Workflow:

Level 1 (Automated):
- Auto-close known false positives
- Auto-escalate critical alerts
- Auto-enrich with context
- Auto-correlate related events

Level 2 (Junior Analysts):
- Review medium/low priority alerts
- Follow runbooks
- Escalate if unsure
- Close false positives

Level 3 (Senior Analysts):
- Complex investigations
- Threat hunting
- Playbook development
- Mentor L1/L2

Level 4 (Incident Responders):
- Active incidents
- Forensics
- Containment/eradication
- Post-incident reviews

Prioritization Scoring:

Base Score:
- Alert severity (from source)
- Asset criticality (production server > dev workstation)
- User criticality (CEO > contractor)
- Data sensitivity (PII database > logging server)

Context Modifiers:
- Known attacker IP (+high priority)
- Active campaign (threat intel) (+high)
- Repeated alerts (+medium)
- After-hours activity (+medium)
- Geographic anomaly (+medium)

ML-based Scoring:
- Train on historical data (what was real vs FP?)
- Features: time, source, destination, alert type, frequency
- Predict probability of true positive
- Continuously retrain with analyst feedback

Incident Categories:

Severity 1 (Critical):
- Active data breach
- Ransomware outbreak
- Critical infrastructure compromise
- Widespread outage
- Response: Immediate, all hands

Severity 2 (High):
- Compromised user account
- Malware detection
- Unauthorized access
- DDoS attack
- Response: Within 1 hour

Severity 3 (Medium):
- Policy violations
- Suspicious activity
- Failed attack attempts
- Response: Within 4 hours

Severity 4 (Low):
- False positives
- Informational alerts
- Successful blocks (no compromise)
- Response: Review during business hours

Analyst Workflow:

Alert Arrives:
1. Review alert details
2. Gather context (who, what, when, where)
3. Check threat intel (known bad?)
4. Review similar past incidents
5. Determine if true positive or false positive

If False Positive:
- Document reason
- Close alert
- Update detection rules (reduce future FPs)

If True Positive:
- Create incident case
- Assess severity and impact
- Contain threat (isolate system, block IP)
- Collect evidence
- Eradicate threat
- Document findings
- Create post-incident report

Investigation Tools:

SIEM Query:
- Search logs for related events
- Build timeline
- Pivot from IP to user to asset

EDR Investigation:
- Process tree analysis
- File analysis
- Network connections
- Registry changes
- Memory dump

Threat Intelligence:
- IP/domain reputation lookup
- File hash lookup (VirusTotal)
- Indicator enrichment
- Related campaigns

Forensics:
- Disk imaging
- Memory analysis
- Network traffic capture
- Log collection

Playbooks & Automation:

Phishing Response:
1. Receive phishing alert
2. Extract IOCs (URLs, sender, attachment hashes)
3. Query email gateway (who else received?)
4. Check endpoint (did anyone click link?)
5. If clicked: isolate endpoint, collect forensics
6. Block sender domain (email gateway)
7. Block URLs (proxy/firewall)
8. Notify affected users
9. Create awareness training
10. Close case

Malware Response:
1. EDR alerts on malware
2. Isolate infected endpoint
3. Collect forensics (process dump, memory, files)
4. Analyze malware (sandbox, reverse engineering)
5. Search for IOCs across environment
6. Block C2 communications
7. Remediate infected systems
8. Patch vulnerability (if exploited)
9. Post-incident report

Compromised Credentials:
1. Unusual login detected (impossible travel)
2. Verify with user (was this you?)
3. If not user: force password reset
4. Revoke active sessions
5. Review account activity (what did attacker do?)
6. Check for persistence (backdoors, new accounts)
7. MFA enforcement
8. Enhanced monitoring

Threat Intelligence Integration:

Feeds:
- Commercial (CrowdStrike, Recorded Future)
- Open source (MISP, AlienVault OTX)
- ISACs (industry-specific)
- Internal (from investigations)

Use Cases:
- Alert enrichment (is this IP bad?)
- Proactive blocking (block known bad IPs)
- Threat hunting (search for IOCs)
- Context for investigations

Bidirectional Sharing:
- Consume external intel
- Share internal findings (anonymized)
- Community defense

Metrics & KPIs:

Detection Metrics:
- Mean Time to Detect (MTTD)
- True positive rate
- False positive rate
- Alert volume trends
- Detection coverage (MITRE ATT&CK)

Response Metrics:
- Mean Time to Respond (MTTR)
- Mean Time to Contain (MTTC)
- SLA compliance (% within SLA)
- Incident backlog
- Repeat incidents

Analyst Metrics:
- Alerts reviewed per shift
- Cases closed per analyst
- Escalation rate
- Average handling time
- Quality score (accuracy)

Business Metrics:
- Total incidents
- Critical incidents
- Financial impact prevented
- Compliance violations
- Customer-facing incidents

Shift Structure:

24/7 Coverage:
- Follow-the-sun (Asia → Europe → Americas)
- Or rotating shifts (each team does all shifts)

Shift Handoff:
- Active incidents (what's ongoing?)
- Escalated cases (need senior review)
- Emerging threats (what to watch)
- System issues (tools down?)

On-Call:
- Tier 3 analysts on-call for escalations
- Incident response team for critical incidents
- Management for severity 1

Technology Stack:

Core:
- SIEM (Splunk, Elastic, Microsoft Sentinel)
- EDR (CrowdStrike, SentinelOne, Microsoft Defender)
- SOAR (Palo Alto XSOAR, Splunk Phantom)
- Threat Intel Platform (TIP)
- Case Management (ServiceNow, JIRA)

Supporting:
- Network monitoring (IDS/IPS, NDR)
- Cloud security (CSPM, CWPP)
- Email security (Proofpoint, Mimecast)
- Forensics tools (EnCase, FTK, Velociraptor)

Challenges:

Alert Fatigue:
- Too many alerts
- Analyst burnout
- Real threats missed
- Solution: Better tuning, automation

Skill Gap:
- Hard to hire skilled analysts
- Continuous training needed
- Junior analysts need mentorship
- Solution: Training programs, career paths

Tool Sprawl:
- Too many tools (30+ is common)
- Context switching overhead
- Integration challenges
- Solution: Consolidation, SOAR

Burnout:
- Stressful work
- Night shifts
- High stakes
- Solution: Mental health support, rotation

Best Practices:
- Tune, tune, tune (reduce false positives)
- Automate tier 1 tasks (let analysts focus on real threats)
- Continuous training (attackers evolve, so must we)
- Playbooks for common scenarios (consistency)
- Metrics-driven improvement (what can we optimize?)
- Blameless post-mortems (learn from incidents)
- Career development (retain talent)
```

**Expected Depth:**
- Specific SIEM/SOAR tool capabilities
- Alert triage automation strategies
- Analyst career progression
- Metrics for SOC effectiveness

---

## 🎓 **HOW TO PRACTICE SYSTEM DESIGN QUESTIONS**

### **Week-by-Week Practice Plan:**

**Weeks 1-2: Foundations (Questions 1-10)**
- Authentication & Identity systems
- Cloud security architectures
- Practice: 1 question every 2 days
- Method: 60-min timer, draw diagrams, explain out loud

**Weeks 3-4: Detection & Network (Questions 11-20)**
- Detection & response systems
- Network & perimeter security
- Practice: 1 question every 2 days
- Focus: Threat modeling, trade-offs

**Weeks 5-6: Data & Application (Questions 21-30)**
- Data protection systems
- Application security
- Practice: 1 question per day
- Add: Mock interviews with peers

**Weeks 7-8: Advanced Topics (Questions 31-40)**
- Supply chain security
- SOC operations
- Advanced platforms
- Practice: 1 question per day
- Simulate: Full interview conditions

### **Practice Method:**

**Solo Practice (60 minutes per question):**
1. Read question (2 min)
2. Clarify requirements (5 min - write down assumptions)
3. High-level design (15 min - draw architecture)
4. Deep dive (25 min - pick 2-3 components, go deep)
5. Trade-offs (10 min - discuss alternatives)
6. Review (3 min - what did you miss?)

**With Partner:**
- Partner plays interviewer
- Asks probing questions
- Challenges your decisions
- Provides feedback

**Record Yourself:**
- Video/audio record your explanation
- Watch back, identify improvements
- Are you clear? Confident? Thorough?

### **Common Mistakes to Avoid:**

❌ Jumping to implementation details without high-level design
❌ Ignoring scalability requirements
❌ Forgetting to discuss monitoring/alerting
❌ Not considering threat model
❌ Overcomplicating with unnecessary components
❌ Underestimating operational complexity
❌ Ignoring cost implications
❌ No discussion of failure modes

### **Evaluation Checklist:**

After each practice, ask:
- ✅ Did I clarify requirements first?
- ✅ Did I draw a clear architecture diagram?
- ✅ Did I identify trust boundaries?
- ✅ Did I discuss specific threats?
- ✅ Did I explain trade-offs?
- ✅ Did I consider scale?
- ✅ Did I mention monitoring?
- ✅ Did I discuss failure scenarios?
- ✅ Was I structured in my approach?
- ✅ Could I explain it to a non-expert?

---

## 🎯 **FINAL COMPREHENSIVE PREP SUMMARY**

You now have:
- ✅ **65 coding questions** (security-focused)
- ✅ **15 supplementary algorithm questions** (fundamentals)
- ✅ **40 system design questions** (security architectures)

**Total: 120 questions covering all interview formats**

**Recommended Timeline: 12-14 weeks**
- Weeks 1-8: Coding (65 + 15 questions)
- Weeks 9-14: System Design (40 questions)
- Ongoing: Hands-on labs, reading, mock interviews

**You're ready when:**
- You can code medium problems in 30-40 min
- You can design secure systems with clear threat models
- You can explain trade-offs confidently
- You have hands-on experience to reference
- You can stay calm under pressure

Good luck with your Big Tech security engineering interviews! 🚀🔐
