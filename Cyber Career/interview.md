# Big Tech Security Engineering Interview Map (Red Team + Cloud Security Focus)

Based on real interview patterns, industry practices, and what actually gets people hired at FAANG/Big Tech for security roles.

---

## 🎯 **INTERVIEW PIPELINE REALITY CHECK**

### **Timeline: 4-8 weeks from application to offer**

```
Week 1-2: Recruiter Screen → Technical Screen
Week 3-5: Virtual Onsite (4-6 rounds in 1-2 days)
Week 6-8: Team matching + Offer negotiation
```

---

## 📋 **THE ACTUAL ROUNDS (What Really Happens)**

### **Round 0: Resume Screen (Before Human Contact)**

**What triggers the phone call:**
- ✅ Clear security impact metrics ("Reduced attack surface by 40%")
- ✅ Production security tools you built (with GitHub links)
- ✅ Real incident response experience
- ✅ Cloud platform certifications (AWS Security Specialty, OSCP, etc.)
- ✅ Contributions to security open source projects
- ✅ Specific tool expertise (not just "familiar with")

**What gets filtered out:**
- ❌ "Responsible for security" (too vague)
- ❌ Only CTF experience, no production work
- ❌ Long tool lists without context
- ❌ No measurable impact
- ❌ Generic "team player" buzzwords

**Action items:**
- Quantify everything: "Detected 23 critical vulnerabilities", "Automated detection reducing MTTD by 75%"
- Show building, not just using: "Built automated cloud misconfiguration scanner"
- Include links: GitHub repos, blog posts, conference talks

---

### **Round 1: Recruiter Screen (30 min)**

**Not just logistics - actual evaluation happens here**

**Questions you'll get:**
1. "Walk me through your security background"
2. "What's your ideal security role?" (Red Team vs Blue Team vs Cloud vs AppSec)
3. "Tell me about a significant security project you led"
4. "What motivates you in security work?"
5. "Why [Company]?" (Research their security culture beforehand)

**What they're really checking:**
- Can you tell a coherent story about your security journey?
- Do you have actual depth or just certifications?
- Are you a team player or lone-wolf hacker?
- Communication skills (critical for security roles)
- Genuine interest vs just chasing FAANG money

**Red flags that kill you here:**
- ❌ "I can do any security role" (shows no focus)
- ❌ Can't explain what you actually did (vs your team)
- ❌ Badmouthing previous companies/teams
- ❌ Entitled attitude ("I deserve to work here")
- ❌ Can't articulate why you want THIS company

**How to ace it:**
```
Prepare 3 stories:
1. Best security win (technical + impact)
2. Hardest security challenge (how you solved it)
3. Collaboration story (working with resistant engineering team)

Each story: 2-3 minutes, with metrics
```

---

### **Round 2: Technical Security Screen (60 min, 1 interviewer)**

**This is the gatekeeper round - 60% of candidates fail here**

**Format:** Live technical discussion, possibly with light coding

**Topics (Red Team focus):**

#### **Part A: Security Fundamentals (15 min)**
- "Explain the difference between authentication and authorization with real examples"
- "Walk me through a TLS handshake"
- "How does OAuth2 work? What are common misconfigurations?"
- "Explain CORS and how it can be exploited"
- "What's the difference between symmetric and asymmetric encryption? When do you use each?"

**They want:** Depth, not Wikipedia definitions. Connect to real attacks.

#### **Part B: Attack Scenarios (20 min)**
Real questions from actual interviews:

**Scenario 1:** "You discover an internal API endpoint that's publicly accessible. Walk me through your investigation."

**What they're evaluating:**
```
1. Reconnaissance (what do you check first?)
2. Impact assessment (what data is exposed?)
3. Attack chaining (what else can you reach?)
4. Communication (how do you report this?)
```

**Scenario 2:** "An application accepts user-uploaded files. What security concerns do you have?"

**Expected coverage:**
- File type validation bypass
- Path traversal
- XXE attacks
- Malware upload
- Storage permissions
- Content-type confusion
- Image processing vulnerabilities (ImageTragick)

**Scenario 3:** "You're testing a web app and notice it reflects user input. Walk me through your testing approach."

**They want to see:**
- XSS understanding (reflected, stored, DOM-based)
- CSP bypass techniques
- Context-aware testing
- Impact demonstration
- Remediation recommendations

#### **Part C: Cloud Security (15 min - critical for cloud roles)**

**Real questions:**
- "An S3 bucket is publicly readable. What's your investigation process?"
- "Explain AWS IAM privilege escalation paths"
- "How would you secure a multi-tenant Kubernetes cluster?"
- "What's the difference between security groups and NACLs? When do you use each?"
- "Explain SSRF in cloud context and why it's dangerous"

**Red Team specific:**
- "You've compromised an EC2 instance. What's your next move?"
- "How do you escalate from a container to the host?"
- "Explain metadata service exploitation"

#### **Part D: Light Coding/Scripting (10 min)**

**Not LeetCode - practical security tasks:**

Example: "Write a Python function that checks if a URL is safe to visit (basic sanitization)"

```python
def is_safe_url(url):
    # They want to see:
    # - Input validation
    # - Protocol checking
    # - Domain validation
    # - Path traversal prevention
    # - Error handling
    pass
```

Example: "Parse this log file and extract failed SSH login attempts"

```python
def parse_ssh_logs(log_file):
    # They evaluate:
    # - Regex usage
    # - Error handling
    # - Data structure choice
    # - Output format
    pass
```

**Passing criteria:**
- Working code (doesn't have to be perfect)
- Security mindset (validate inputs, handle errors)
- Clear thinking process (talk through your approach)
- Clean syntax (no syntax errors from "typos")

---

### **Round 3: Coding/Automation Round (60 min, 1 interviewer)**

**More substantial than technical screen, but still security-focused**

**Format:** Live coding in Python/Go, shared editor

**Difficulty level:** LeetCode Easy-Medium equivalent, but security-themed

#### **Example Problems (Real Interview Questions):**

**Problem 1: Log Analysis**
```
Given a list of log entries with timestamps, IP addresses, and actions,
identify IPs with more than N failed login attempts within M minutes.

Input:
[
  {"timestamp": "2024-01-01 10:00:00", "ip": "1.2.3.4", "action": "login_failed"},
  {"timestamp": "2024-01-01 10:01:00", "ip": "1.2.3.4", "action": "login_failed"},
  ...
]

Output: List of suspicious IPs
```

**What they're testing:**
- Time window handling
- Hash map usage
- Sliding window concept
- Edge cases (time zones, rate limiting logic)

**Problem 2: Network Scanner**
```
Write a function that checks if a port is open on a given host.
Then extend it to scan multiple ports concurrently.
```

**What they're testing:**
- Socket programming basics
- Concurrency (threading/async)
- Error handling (timeouts, connection refused)
- Resource management

**Problem 3: Config Validator**
```
Given a firewall rule configuration (JSON/dict), validate that:
1. No rule allows 0.0.0.0/0 on port 22
2. All rules have required fields
3. Port ranges are valid
```

**What they're testing:**
- Data structure navigation
- Validation logic
- Security policy understanding
- Error reporting

**Problem 4: Simple Detection Rule**
```
Write a function that detects command injection attempts in user input.
Consider: shell metacharacters, encoded inputs, bypass techniques
```

**What they're testing:**
- Pattern matching
- Security knowledge (what characters are dangerous?)
- Bypass awareness (URL encoding, Unicode tricks)
- False positive handling

#### **Coding Round Strategy:**

**Time allocation:**
```
5 min: Clarify requirements, ask questions
35 min: Code the solution (talk through your thinking)
10 min: Test with examples, handle edge cases
10 min: Discuss improvements, trade-offs
```

**What gets you points:**
- ✅ Ask clarifying questions first
- ✅ Start with brute force, then optimize
- ✅ Test as you code (don't wait for them to ask)
- ✅ Discuss trade-offs (performance vs accuracy)
- ✅ Mention edge cases (empty input, malformed data)

**What kills you:**
- ❌ Jump into coding without understanding
- ❌ Silent coding (they can't read your mind)
- ❌ Syntax errors (practice basic Python!)
- ❌ No testing (write test cases yourself)
- ❌ Defensive when given hints

---

### **Round 4: Security System Design (60 min, 1 interviewer)**

**This is where seniors separate from juniors**

**Format:** Whiteboard/diagramming tool, collaborative discussion

**Not like SWE system design - security is the primary lens**

#### **Example Problems:**

**Problem 1: Design a Secrets Management System**

**Initial prompt:** "Design a system that stores and distributes secrets (API keys, passwords) to applications securely."

**What they expect you to cover:**

```
1. Requirements Clarification (5 min):
   - Scale: How many secrets? How many requests/sec?
   - Users: Humans only or apps too?
   - Secret types: Static vs dynamic secrets?
   - Compliance: Any specific requirements?

2. High-Level Design (15 min):
   ┌─────────────┐
   │   Clients   │
   │ (Apps/Users)│
   └──────┬──────┘
          │ (mTLS)
   ┌──────▼──────────┐
   │  API Gateway    │ ← Rate limiting, authN
   │  (Load Balanced)│
   └──────┬──────────┘
          │
   ┌──────▼──────────┐
   │ Secrets Service │ ← Authorization logic
   └──────┬──────────┘
          │
   ┌──────▼──────────┐
   │ Encrypted Store │ ← HSM/KMS for master key
   │  (Vault/Cloud)  │
   └─────────────────┘

3. Deep Dive Topics (25 min):

   Authentication:
   - mTLS for service-to-service
   - OAuth2 for user access
   - Short-lived tokens

   Authorization:
   - RBAC vs ABAC?
   - Least privilege
   - Audit logging

   Encryption:
   - Encryption at rest (AES-256)
   - Master key management (HSM or cloud KMS)
   - Key rotation strategy

   Secret Rotation:
   - Automated rotation
   - Zero-downtime updates
   - Notification mechanism

   Audit & Monitoring:
   - Who accessed what, when?
   - Failed access attempts
   - Anomaly detection

4. Threat Modeling (10 min):

   "How does this system fail?"

   Threats:
   - Compromised client credentials
   - Insider threat (admin abuse)
   - Network interception
   - Storage breach
   - Side-channel attacks

   Mitigations:
   - Short-lived credentials
   - Audit logging + alerting
   - mTLS everywhere
   - Encryption at rest + in transit
   - Rate limiting + anomaly detection

5. Trade-offs (5 min):
   - Performance vs Security (caching secrets?)
   - Availability vs Consistency (CAP theorem)
   - Usability vs Security (friction for developers)
```

**Problem 2: Design Secure Authentication for a Multi-Tenant SaaS**

**Scope:**
- 10,000 companies (tenants)
- 1M users total
- SSO support required
- Mobile + web clients

**Expected coverage:**
```
1. Authentication Flow
   - Password-based (with MFA)
   - SSO (SAML/OIDC)
   - API tokens for programmatic access
   
2. Session Management
   - Token-based (JWT vs opaque tokens?)
   - Refresh token rotation
   - Session invalidation

3. Tenant Isolation
   - Data isolation strategies
   - Subdomain vs path-based routing
   - Cross-tenant access prevention

4. Security Controls
   - Password policies
   - Brute force protection
   - Account takeover detection
   - Device fingerprinting

5. Threat Scenarios
   - Token theft
   - Session fixation
   - Phishing attacks
   - Insider threats
```

**Problem 3: Design a Cloud Security Monitoring System**

**Scope:** Monitor security across 1000+ AWS accounts

**Expected coverage:**
```
1. Data Collection
   - CloudTrail logs
   - VPC Flow Logs
   - GuardDuty findings
   - Config snapshots
   
2. Detection Logic
   - Rule-based detection
   - Anomaly detection (ML)
   - Threat intelligence correlation
   
3. Alert Management
   - Alert prioritization
   - Deduplication
   - Incident enrichment
   
4. Response Automation
   - Automated remediation
   - Isolation workflows
   - Escalation procedures

5. Threat Examples to Detect
   - Unusual API calls
   - Resource exposure
   - Privilege escalation
   - Data exfiltration
   - Crypto mining
```

#### **System Design Scoring Rubric:**

**What gets you hired:**
- ✅ Start with requirements/constraints
- ✅ Draw clear diagrams with trust boundaries
- ✅ Identify threats without prompting
- ✅ Explain trade-offs (don't just say "it depends")
- ✅ Think operationally (how do you maintain this?)
- ✅ Discuss defense in depth (multiple layers)

**What fails you:**
- ❌ Jump straight to tools without reasoning
- ❌ Ignore threat modeling
- ❌ No mention of monitoring/logging
- ❌ Perfect security with no trade-offs
- ❌ Can't explain your design choices

---

### **Round 5: Red Team / Cloud Security Deep Dive (60 min, 1-2 interviewers)**

**This is domain-specific expertise validation**

**Format:** Technical deep dive, possibly hands-on demonstration

#### **For Red Team Roles:**

**Part A: Attack Methodology (20 min)**

"Walk me through how you'd compromise a typical corporate environment, from external reconnaissance to domain admin."

**Expected kill chain:**
```
1. Reconnaissance
   - OSINT gathering
   - Subdomain enumeration
   - Technology fingerprinting
   - Email harvesting

2. Initial Access
   - Phishing techniques
   - Public-facing app exploitation
   - Supply chain compromise
   - Credential stuffing

3. Execution & Persistence
   - Malware delivery
   - Living off the land
   - Scheduled tasks/services
   - Registry modifications

4. Privilege Escalation
   - Kernel exploits
   - Misconfigured services
   - Token manipulation
   - GPO abuse

5. Lateral Movement
   - Pass-the-hash
   - Kerberoasting
   - WMI/PS Remoting
   - RDP exploitation

6. Data Exfiltration
   - Stealth techniques
   - Encrypted channels
   - DNS tunneling
   - Cloud storage abuse
```

**Part B: OPSEC & Tradecraft (15 min)**

"How do you avoid detection during red team engagements?"

**Topics to cover:**
- Blending with normal traffic
- Evasion techniques (AV bypass, EDR evasion)
- C2 infrastructure design
- Payload obfuscation
- Attribution challenges

**Part C: Tool Knowledge (15 min)**

They may ask about specific tools:
- "Explain how Cobalt Strike beacons work"
- "What's the difference between Mimikatz and Rubeus?"
- "How do you customize exploitation frameworks?"
- "Tell me about a tool you've built or modified"

**Part D: Reporting & Impact (10 min)**

"You've compromised a production database. How do you report this to the client without causing panic?"

**They want:**
- Clear, actionable findings
- Business impact articulation
- Remediation priorities
- Evidence preservation
- Professional communication

#### **For Cloud Security Roles:**

**Part A: Cloud Attack Scenarios (25 min)**

**Scenario 1:** "You find AWS credentials in a public GitHub repo. Walk me through exploitation."

**Expected steps:**
```
1. Validate credentials (aws sts get-caller-identity)
2. Enumerate permissions (enumerate-iam.py, ScoutSuite)
3. Check for privilege escalation paths
4. Identify sensitive resources (S3, EC2, RDS, Secrets Manager)
5. Lateral movement opportunities
6. Persistence mechanisms
7. Impact assessment
```

**Scenario 2:** "An S3 bucket is configured as public. What's your investigation checklist?"

**Expected coverage:**
```
- Check bucket policy vs ACLs
- Review CloudTrail logs (who made it public?)
- Audit object-level access (who downloaded what?)
- Check for similar misconfigurations
- Assess data sensitivity
- Containment steps
- Preventive controls
```

**Scenario 3:** "Design security for a Kubernetes cluster running multi-tenant workloads."

**Expected coverage:**
```
- Namespace isolation
- RBAC configuration
- Network policies
- Pod security policies/standards
- Secrets management
- Container image scanning
- Runtime security (Falco)
- Admission controllers
```

**Part B: Cloud Platform Deep Dive (20 min)**

Pick your strongest platform (AWS/Azure/GCP):

**AWS-specific questions:**
- "Explain IAM policy evaluation logic"
- "How do you secure cross-account access?"
- "What's the difference between SCPs and IAM policies?"
- "Explain AWS Cognito security considerations"
- "How would you implement just-in-time access?"

**Part C: Detection & Response in Cloud (15 min)**

"How do you detect and respond to cloud security incidents?"

**Topics:**
- Log sources (CloudTrail, VPC Flow, Guard Duty)
- SIEM integration
- Automated response (Lambda + EventBridge)
- Forensics in cloud (snapshot analysis)
- Container/serverless security monitoring

---

### **Round 6: Incident Response Scenario (45-60 min, 1-2 interviewers)**

**This is the "pressure test" round - can you think clearly under stress?**

**Format:** Live scenario, you're on-call, incident is happening NOW

#### **Common Scenarios:**

**Scenario 1: Production Key Leak**

```
🚨 INCIDENT: 3:00 AM Slack Alert

"AWS keys found in public GitHub repo, committed 2 hours ago.
 Keys belong to prod-api service account. What do you do?"
```

**What they're evaluating:**

**Immediate actions (first 15 min):**
```
1. Rotate compromised credentials IMMEDIATELY
2. Check CloudTrail for unauthorized access
3. Identify what permissions the keys had
4. Assess blast radius (what could be compromised?)
5. Alert security team & stakeholders
```

**Investigation (next 20 min):**
```
- Review CloudTrail logs thoroughly
- Check for unusual API calls
- Identify any data access/exfiltration
- Look for persistence mechanisms
- Review recent resource changes
```

**Containment & Recovery:**
```
- Isolate affected resources if needed
- Implement additional monitoring
- Update detection rules
- Document timeline
```

**Post-Incident:**
```
- Root cause analysis
- Preventive measures (secret scanning, pre-commit hooks)
- Team training
- Process improvements
```

**They're watching for:**
- ✅ Prioritization (fix before investigate)
- ✅ Calm, methodical thinking
- ✅ Communication (who do you notify?)
- ✅ Documentation mindset
- ✅ Learning mentality (how to prevent)

**Scenario 2: Ransomware Detection**

```
🚨 INCIDENT: 10:00 AM

"EDR alerts showing file encryption activity on 15 Windows servers.
 Encrypted file extensions: .locked
 Activity started 30 minutes ago. What's your response?"
```

**Your response framework:**

**Immediate (first 10 min):**
- Isolate affected systems (network segmentation)
- Stop the spread (block lateral movement)
- Identify patient zero
- Alert executive leadership

**Investigation:**
- Determine ransomware variant
- Check backup integrity
- Assess encryption scope
- Look for indicators of compromise

**Recovery:**
- Restore from backups (if available)
- Rebuild compromised systems
- Patch vulnerabilities
- Strengthen controls

**Scenario 3: Suspicious Cloud Activity**

```
🚨 INCIDENT: 2:00 PM

"GuardDuty alert: Unusual API activity from prod account.
 - Region: us-east-1 (we don't use this region)
 - Action: Large-scale EC2 instance launches
 - User: service-account-prod
 What do you do?"
```

**Expected response:**
```
1. Verify alert legitimacy (not false positive)
2. Terminate unauthorized instances
3. Rotate service account credentials
4. Check billing for crypto mining indicators
5. Review CloudTrail for attack timeline
6. Identify compromise vector
7. Implement preventive controls (SCPs, region restrictions)
```

#### **Incident Response Scoring:**

**Strong candidates:**
- Triage correctly (contain first, investigate later)
- Ask clarifying questions
- Think about business impact
- Communicate clearly throughout
- Consider legal/compliance implications
- Learn from the incident

**Weak candidates:**
- Panic or freeze
- Jump to conclusions without data
- Ignore stakeholder communication
- Focus only on technical details
- No post-incident improvement mindset

---

### **Round 7: Behavioral / Collaboration (45-60 min, 1-2 interviewers)**

**Often with hiring manager or team lead - culture fit is CRITICAL**

**This round has ended many candidates who aced technical rounds**

#### **Common Questions & What They Really Mean:**

**Question 1:** "Tell me about a time you had to push back on a developer who disagreed with your security finding."

**What they're really asking:**
- Can you influence without authority?
- Do you collaborate or dictate?
- Can you see the developer's perspective?
- How do you handle conflict?

**Good answer structure (STAR + Security context):**
```
Situation: "A developer wanted to deploy code that stored passwords in plaintext"

Task: "I needed to prevent the security issue while maintaining the relationship"

Action:
- Met with developer to understand their constraints (tight deadline)
- Explained the risk clearly with real examples (breach cost)
- Offered to pair-program a secure solution (hashing library)
- Provided documentation and future support
- Escalated timeline with their manager collaboratively

Result:
- Code deployed securely, only 2 days delayed
- Developer learned about secure password storage
- Created a security library others could use
- Improved team relationship
```

**Bad answer:**
"I told them it was a security vulnerability and they had to fix it. I escalated to their manager when they resisted."

**Question 2:** "Describe a time when you were wrong about a security issue."

**What they're really asking:**
- Do you have self-awareness?
- Can you admit mistakes?
- Do you learn from failures?
- Are you humble?

**Good answer:**
```
Situation: "I flagged a 'critical SQL injection' in production code"

What I got wrong:
- Didn't verify exploitability (ORM prevented actual injection)
- Caused unnecessary panic
- Diverted engineering resources

What I learned:
- Always verify findings before escalating severity
- Understand the technology stack deeply
- Severity should match actual risk, not theoretical
- Built a verification checklist for future findings

Positive outcome:
- Improved my testing methodology
- Created better severity classification guidelines
- Team trusted my findings more after I owned the mistake
```

**Question 3:** "Tell me about the most impactful security project you've led."

**What they're really asking:**
- Can you drive projects independently?
- Do you think about business impact?
- Can you influence stakeholders?
- How do you measure success?

**Good answer structure:**
```
Project: "Built automated cloud security monitoring across 500 AWS accounts"

Context:
- Security team manually checking configurations weekly
- Missing critical misconfigurations for days
- No consistent standards

My approach:
- Interviewed stakeholders (dev teams, ops, compliance)
- Designed detection rules based on real incidents
- Built automation with Python + AWS Lambda
- Created dashboard for visibility
- Rolled out incrementally with team feedback

Impact (quantified):
- Reduced MTTD from 7 days to 15 minutes
- Detected 127 misconfigurations in first month
- Prevented 3 potential data exposures
- Saved security team 20 hours/week
- Adopted by 100% of product teams

What I learned:
- Automation only works with good detection logic
- Stakeholder buy-in is critical
- False positives kill trust
```

**Question 4:** "How do you stay current with security trends?"

**What they're really asking:**
- Are you genuinely passionate about security?
- Do you self-educate?
- Can you separate signal from noise?

**Good answer:**
```
My learning stack:

Daily:
- Hacker News, r/netsec, security Twitter
- Threat intel feeds (CrowdStrike, Recorded Future)
- CVE monitoring for our tech stack

Weekly:
- Security podcasts (Risky Business, Darknet Diaries)
- Blog posts (Krebs, Schneier, cloud provider security blogs)
- Vulnerability research write-ups

Monthly:
- Hands-on labs (HackTheBox, TryHackMe)
- Security conferences (virtual attendance)
- Tool experimentation

Continuous:
- Working on personal security projects
- Contributing to open source security tools
- Writing blog posts about findings

Recent example:
"Last month I learned about [specific vulnerability]. I tested if we were vulnerable, we weren't, but I added detection rules anyway and shared findings with the team."
```

**Question 5:** "Why do you want to work here specifically?"

**What they're really asking:**
- Did you research us?
- Are you genuinely interested or just applying everywhere?
- Do you understand our security challenges?

**Good answer (example for a cloud company):**
```
Three specific reasons:

1. Technical challenges:
   "Your multi-cloud, multi-region infrastructure at scale presents unique security challenges. I'm particularly interested in how you handle [specific challenge they've written about]."

2. Team & culture:
   "I've read [team member's] blog posts on [topic]. The emphasis on engineering-driven security aligns with my approach."

3. Impact:
   "Securing systems that millions of customers rely on is exactly the kind of impactful work I want to do. Your recent [security initiative] showed me this team takes security seriously."

My specific contribution:
"I could bring experience in [relevant area], and I'm excited to learn from your team about [area you want to grow]."
```

**Bad answer:**
"I want to work at a big tech company for the compensation and resume boost."

#### **Other Behavioral Questions to Prepare:**

- "Tell me about a time you had to make a security decision with incomplete information"
- "Describe a situation where you had to balance security with business needs"
- "How do you prioritize vulnerabilities?"
- "Tell me about a time you missed a security issue. How did you handle it?"
- "Describe your experience working with distributed teams"
- "How do you explain technical security concepts to non-technical stakeholders?"
- "Tell me about a time you had to say no to a feature for security reasons"
- "What's your approach to security debt?"

#### **Behavioral Round Red Flags:**

- ❌ Arrogance ("I'm always right about security")
- ❌ Inflexibility ("Security must never be compromised")
- ❌ Blame others for security failures
- ❌ No examples of collaboration
- ❌ Can't articulate business impact
- ❌ Defensive when challenged
- ❌ No curiosity or learning mindset
- ❌ Us vs them mentality (security vs engineering)

---

## 🎯 **COMPANY-SPECIFIC VARIATIONS**

### **Meta (Facebook)**

**Unique aspects:**
- Heavier coding emphasis (may include SWE-style coding round)
- Strong focus on scale (billions of users)
- "Move fast" culture - security must enable, not block
- Cross-functional collaboration heavily weighted

**Prep focus:**
- Practice coding more (LeetCode medium level)
- Think about security at massive scale
- Prepare "enabling security" stories

### **Google**

**Unique aspects:**
- Very structured interview process (most predictable)
- Googleyness matters (humble, collaborative)
- Strong emphasis on fundamentals
- May include system design for SWE standards

**Prep focus:**
- Deep fundamentals (crypto, networking, OS internals)
- Scalable security solutions
- Clean, well-tested code
- Humility in presentation

### **Amazon (AWS)**

**Unique aspects:**
- Leadership Principles dominate behavioral rounds
- Customer obsession matters (even in security)
- "Dive deep" - expect very technical questions
- May involve writing docs/proposals

**Prep focus:**
- Map stories to Leadership Principles
- Deep AWS knowledge (if cloud security role)
- Think like a customer
- Practice writing (1-pagers, 6-pagers)

### **Microsoft (Azure)**

**Unique aspects:**
- Enterprise security mindset
- Strong Windows/AD knowledge valuable
- Identity & access management focus
- Growth mindset (learning > knowing)

**Prep focus:**
- Windows security internals
- Active Directory exploitation/defense
- Azure security services
- Show willingness to learn

### **Apple**

**Unique aspects:**
- Extremely secretive (NDAs everywhere)
- Strong focus on privacy
- Hardware security knowledge valuable
- Culture fit is paramount

**Prep focus:**
- Understand Apple's privacy stance
- Mobile/hardware security
- Discrete, trustworthy presentation
- Passion for user privacy

---

## 📚 **PREPARATION ROADMAP (12-Week Plan)**

### **Weeks 1-4: Foundation Building**

**Week 1: Security Fundamentals Review**
- [ ] Authentication & authorization mechanisms
- [ ] Cryptography basics (symmetric, asymmetric, hashing, PKI)
- [ ] Network protocols (TCP/IP, TLS, DNS, HTTP/HTTPS)
- [ ] OWASP Top 10 + exploitation techniques
- [ ] Common attack vectors (XSS, SQLi, CSRF, SSRF, etc.)

**Resources:**
- PortSwigger Web Security Academy (free, excellent)
- OWASP Testing Guide
- Crypto101 book

**Week 2: Cloud Security Fundamentals**
- [ ] AWS security fundamentals (IAM, VPC, S3, CloudTrail)
- [ ] Azure/GCP basics (if relevant to target company)
- [ ] Shared responsibility model
- [ ] Common cloud misconfigurations
- [ ] Cloud attack paths (SSRF→metadata, IAM abuse, etc.)

**Resources:**
- AWS Security Specialty exam study guide
- flAWS.cloud (free AWS security challenges)
- CloudGoat (vulnerable by design AWS environment)

**Week 3: Hands-On Labs - Offensive**
- [ ] HackTheBox or TryHackMe (10-15 machines)
- [ ] Focus on Active Directory / Windows
- [ ] Practice writing exploitation scripts
- [ ] Document your methodology

**Goal:** Fluency in attack chains, not just tool usage

**Week 4: Hands-On Labs - Cloud**
- [ ] Complete flAWS.cloud
- [ ] Run CloudGoat scenarios
- [ ] Practice with AWS CLI/boto3
- [ ] Build a simple security scanner

**Goal:** Comfort with cloud CLIs and attack patterns

### **Weeks 5-8: Technical Skill Building**

**Week 5: Coding Practice**
- [ ] 20-25 LeetCode Easy problems (arrays, strings, hash maps)
- [ ] Focus on security-relevant patterns
- [ ] Practice explaining your code clearly

**Daily commitment:** 2-3 problems

**Week 6: Security-Focused Coding**
- [ ] Build log parser in Python
- [ ] Write network scanner
- [ ] Create config validator
- [ ] Build simple detection rules

**Goal:** Portfolio of security tools you can demo

**Week 7: System Design Study**
- [ ] Read system design resources (focus on security aspects)
- [ ] Practice threat modeling frameworks (STRIDE)
- [ ] Sketch 5 secure system designs
- [ ] Practice explaining trade-offs

**Week 8: More Coding + Labs**
- [ ] 15-20 LeetCode Medium problems
- [ ] More cloud labs (Kubernetes security, container escapes)
- [ ] Red Team labs (if Red Team focus)

### **Weeks 9-11: Interview Simulation**

**Week 9: Mock Technical Screens**
- [ ] 3-5 mock technical interviews
- [ ] Practice explaining security concepts
- [ ] Get feedback from security engineers

**Resources:**
- interviewing.io (paid, security engineers available)
- Pramp (free peer practice)
- Security friends/colleagues

**Week 10: Mock System Design**
- [ ] 3-5 mock system design interviews
- [ ] Practice whiteboarding
- [ ] Time yourself (60 min limit)
- [ ] Record and review

**Week 11: Mock Behavioral**
- [ ] Prepare 10-15 STAR stories
- [ ] Practice with friend/mentor
- [ ] Record yourself (audio/video)
- [ ] Refine based on feedback

### **Week 12: Company Research & Final Prep**

**Company-specific research:**
- [ ] Read security blog posts from target companies
- [ ] Understand their tech stack
- [ ] Research recent security initiatives
- [ ] Connect with employees on LinkedIn

**Final review:**
- [ ] Review fundamentals
- [ ] Practice 5-10 more coding problems
- [ ] Do 1-2 full mock interviews
- [ ] Rest before interview day

---

## 🔧 **ESSENTIAL TOOLS & SKILLS CHECKLIST**

### **Must-Have Technical Skills:**

**Programming:**
- [ ] Python (advanced) - scripting, automation, tool building
- [ ] Go (intermediate) - performance tools
- [ ] Bash (intermediate) - quick automation
- [ ] SQL (intermediate) - log queries

**Cloud Platforms:**
- [ ] AWS (advanced if targeting AWS roles)
- [ ] Understanding of Azure/GCP (basic)
- [ ] IaC (Terraform, CloudFormation)

**Security Tools:**

**Offensive:**
- [ ] Nmap, Masscan (network scanning)
- [ ] Burp Suite (web testing)
- [ ] Metasploit, Cobalt Strike (exploitation frameworks - know them)
- [ ] Bloodhound, Mimikatz (AD exploitation)
- [ ] Impacket (network protocol tools)

**Defensive:**
- [ ] Splunk/ELK (SIEM)
- [ ] Suricata/Snort (IDS)
- [ ] Osquery (endpoint visibility)
- [ ] Prowler/ScoutSuite (cloud security scanning)

**Container/K8s:**
- [ ] Docker security basics
- [ ] Kubernetes security
- [ ] Trivy, Clair (image scanning)
- [ ] Falco (runtime security)

**Development:**
- [ ] Git (version control)
- [ ] CI/CD concepts
- [ ] API security
- [ ] Secrets management

---

## 💡 **INTERVIEW DAY TACTICS**

### **Before the Interview:**

**24 hours before:**
- [ ] Review your project stories
- [ ] Review company security blog
- [ ] Prepare questions for interviewers
- [ ] Set up your environment (quiet space, stable internet)
- [ ] Test video/audio equipment

**2 hours before:**
- [ ] Light technical review (skim notes)
- [ ] Don't cram new material
- [ ] Eat something
- [ ] Use bathroom
- [ ] Set up water nearby

**30 minutes before:**
- [ ] Close unnecessary apps
- [ ] Have notebook + pen ready
- [ ] Breathe deeply
- [ ] Positive mindset

### **During the Interview:**

**Universal tactics:**

1. **Listen completely** before responding
2. **Ask clarifying questions** (shows thoughtfulness)
3. **Think out loud** (they can't read your mind)
4. **Admit when you don't know** something ("I don't know X, but here's how I'd find out...")
5. **Be collaborative** (it's not you vs interviewer)
6. **Watch for hints** (interviewers often guide you)
7. **Manage your time** (don't get stuck on one part)
8. **Check in periodically** ("Am I on the right track?")

**For coding rounds:**
- Start with brute force, optimize later
- Test with examples as you code
- Handle edge cases explicitly
- Discuss time/space complexity

**For system design:**
- Start with requirements/constraints
- Draw diagrams with clear boundaries
- Think about failure modes
- Discuss trade-offs (no perfect solutions)

**For behavioral:**
- Use STAR method (Situation, Task, Action, Result)
- Be honest (they can tell when you're lying)
- Show learning/growth mindset
- Quantify impact when possible

### **Red Flags to Avoid:**

- ❌ Badmouthing previous employers
- ❌ Arrogance or overconfidence
- ❌ Getting defensive when challenged
- ❌ Arguing with interviewer
- ❌ Being completely silent while thinking
- ❌ Giving up too easily
- ❌ Not asking any questions at the end

### **Questions to Ask Interviewers:**

**Good questions:**
- "What does a typical on-call rotation look like?"
- "How does the security team collaborate with product teams?"
- "What's the biggest security challenge the team is facing?"
- "How do you measure security success here?"
- "What does growth look like for someone in this role?"
- "Can you tell me about a recent security project the team worked on?"

**Avoid:**
- Questions about compensation (save for recruiter)
- Questions easily answered by Google
- Only asking about perks/benefits
- Not asking anything (shows disinterest)

---

## 🎓 **POST-INTERVIEW**

### **After Each Round:**

**Within 30 minutes:**
- [ ] Write down what was asked
- [ ] Note what you did well
- [ ] Identify what you could improve
- [ ] Send thank-you email (if appropriate)

**That evening:**
- [ ] Review any topics you struggled with
- [ ] Practice those areas
- [ ] Prepare for next rounds

### **After Full Onsite:**

**Within 24 hours:**
- [ ] Send thank-you emails to interviewers
- [ ] Reflect on overall performance
- [ ] Note any promised follow-ups

**While waiting:**
- [ ] Continue practicing (don't stop)
- [ ] Keep interviewing elsewhere
- [ ] Don't obsess over outcome

### **If You Get the Offer:**

- [ ] Ask for offer details in writing
- [ ] Negotiate (always negotiate)
- [ ] Consider total compensation, not just base salary
- [ ] Ask about team, role, growth opportunity
- [ ] Take time to decide (don't rush)

### **If You Don't Get the Offer:**

- [ ] Ask for feedback (politely)
- [ ] Identify gaps in your performance
- [ ] Create improvement plan
- [ ] Practice those specific areas
- [ ] Apply lessons to next interview

**Remember:** Rejection is normal. Many successful security engineers failed multiple interviews before succeeding.

---

## 📊 **SUCCESS METRICS**

**You're ready when:**

- [ ] You can explain security concepts to a non-technical person
- [ ] You can code a working solution to medium problems in 30-40 min
- [ ] You can design a secure system and defend your choices
- [ ] You have 10+ STAR stories prepared
- [ ] You can threat model a system in real-time
- [ ] You know your resume inside and out
- [ ] You can calmly handle pressure
- [ ] You have hands-on experience to reference

**Reality check:** You don't need to be perfect. You need to be "hireable" - showing potential, learning ability, and cultural fit matter as much as raw knowledge.

---

## 🚀 **FINAL THOUGHTS**

**What actually gets you hired:**

1. **Technical competence** (you can do the job)
2. **Communication skills** (you can work with teams)
3. **Problem-solving mindset** (you can handle unknowns)
4. **Learning agility** (you can grow)
5. **Cultural fit** (you match the team's values)

**Big Tech security is about:**
- Building secure systems, not just breaking them
- Enabling teams, not blocking them
- Collaborating, not dictating
- Continuous learning, not resting on certifications

**Your competitive advantage:**
- Real production security experience > CTF trophies
- Tools you've built > tools you've used
- Clear communication > technical jargon
- Humility + confidence > arrogance
- Learning from failures > pretending perfection

---

**This map is based on:**
- Real interview experiences at FAANG companies
- Conversations with Big Tech security engineers
- Hiring committee insights
- Current industry practices

**Remember:** Interviews are imperfect. Sometimes great candidates don't pass, and that's okay. Keep learning, keep building, keep improving. Your goal is to be undeniably hireable, not perfect.

**Good luck! 🔐**
