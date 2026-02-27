# CloudSecure Competitive Analysis

## Market Landscape Overview
```
Price
  │
  │  Wiz, Orca, Lacework
  │  ($75k-150k/year)
  │  ├─ Enterprise features
  │  ├─ Full CSPM + CWPP
  │  └─ Sales-led, slow
  │
  │  CloudSecure
  │  ($99-499/month)
  │  ├─ Security credit score ⭐
  │  ├─ Multi-account aggregation
  │  ├─ Drift detection
  │  └─ Self-serve SaaS
  │
  │  Prowler, ScoutSuite
  │  (Free/OSS)
  │  ├─ CLI only
  │  ├─ No UI/dashboard
  │  └─ Manual setup
  │
  └─────────────────────────────► Features
```

**Our Position:** Premium OSS alternative with SaaS UX at startup pricing

---

## Competitor Deep Dive

### 1. Wiz (Main Enterprise Competitor)

**Company Info:**
- **Founded:** 2020
- **Funding:** $900M+ raised, $10B valuation
- **Employees:** 1000+
- **HQ:** New York

**Product:**
- **What:** Agentless cloud security (CSPM + CWPP)
- **Price:** $100k-300k+/year (enterprise only)
- **Clouds:** AWS, Azure, GCP, Kubernetes
- **Key Features:**
  - Graph-based security analysis
  - Vulnerability management
  - Container security
  - Compliance frameworks (all of them)
  - Secrets scanning
  - CIEM (Cloud Infrastructure Entitlement Management)

**Strengths:**
- Comprehensive feature set
- Beautiful UI/UX
- Agentless (no performance impact)
- Graph database (shows lateral movement)
- Strong brand (Microsoft acquisition rumors)
- Enterprise support

**Weaknesses:**
- **Price:** $100k+ minimum, startups can't afford
- Long sales cycles (3-6 months)
- Overkill for small teams
- Requires security team to interpret results
- Complex setup despite "agentless"

**Why We Win Against Them:**
- **Price:** 1/100th the cost ($500/mo vs $50k+/year)
- **Speed:** Self-serve in 5 minutes vs 3-month sales cycle
- **Simplicity:** One number (0-100) vs complex dashboards
- **Target:** Built FOR startups, not enterprises

**Who They Win:**
- Series C+ with dedicated security teams
- Enterprises with $100k+ security budgets
- Companies needing full CSPM + CWPP + CIEM

---

### 2. Orca Security (Enterprise Competitor)

**Company Info:**
- **Founded:** 2019
- **Funding:** $550M raised, $1.8B valuation
- **Employees:** 500+
- **HQ:** Los Angeles

**Product:**
- **What:** Cloud security platform (CSPM + CWPP)
- **Price:** $75k-200k+/year
- **Clouds:** AWS, Azure, GCP, Alibaba Cloud
- **Key Features:**
  - SideScanning™ (agentless)
  - Attack path analysis
  - Shift-left security
  - Compliance automation
  - Container & workload security

**Strengths:**
- True agentless (reads cloud APIs only)
- Fast deployment (minutes, not weeks)
- Good visualization
- Strong AWS integration

**Weaknesses:**
- **Price:** Still $75k+ minimum
- Enterprise-focused (not startup-friendly)
- Complex pricing model
- Requires training to use effectively

**Why We Win:**
- **Price:** Startup-friendly ($99-499/mo)
- **Focus:** Security posture score, not everything
- **UX:** Simpler mental model (credit score)

**Who They Win:**
- Series B+ companies
- Mid-market with security budgets
- AWS-heavy organizations

---

### 3. Prowler (Main OSS Competitor)

**Company Info:**
- **Founded:** 2016 (OSS), Prowler Pro 2020
- **Type:** Open-source CLI tool
- **Employees:** ~20 (small team)

**Product:**
- **What:** CLI security scanner
- **Price:** 
  - OSS: Free
  - Pro: ~$10k+/year (unclear pricing)
- **Clouds:** AWS, Azure, GCP, Kubernetes
- **Key Features:**
  - 400+ security checks
  - CIS benchmark compliance
  - JSON/HTML/CSV reports
  - Multi-cloud support

**Strengths:**
- **Free** (OSS version)
- Comprehensive checks (400+)
- Active community
- Well-documented
- CI/CD integration

**Weaknesses:**
- **CLI only** (no dashboard)
- No drift detection
- No historical trending
- No multi-account aggregation
- Technical barrier (requires DevOps knowledge)
- Manual execution
- JSON reports hard to parse

**Why We Win:**
- **Dashboard:** Web UI vs CLI
- **Drift detection:** Track changes over time
- **Credit score:** 0-100 vs 400 separate checks
- **Multi-account:** Aggregate across environments
- **Scheduled:** Auto-run vs manual execution

**Why They Win:**
- Free (we can keep our OSS CLI free too!)
- DevOps teams who prefer CLI
- CI/CD pipeline integration

**Our Strategy:**
- Keep CloudSecure CLI **open-source** (compete with Prowler)
- Charge for **dashboard + multi-account + drift** (value add)
- Open-core model wins both audiences

---

### 4. AWS Security Hub (Cloud-Native Competitor)

**Company Info:**
- **Provider:** AWS native service
- **Price:** Pay-per-use ($0.0010 per check)
- **Integration:** Native AWS service

**Product:**
- **What:** Centralized security findings aggregator
- **Price:** ~$100-500/month (depending on usage)
- **Coverage:** AWS only (not multi-cloud)
- **Key Features:**
  - Aggregates findings from AWS services
  - CIS AWS Foundations Benchmark
  - Integrates with GuardDuty, Inspector, Macie
  - Compliance standards

**Strengths:**
- Native AWS integration
- Cheap (pay-as-you-go)
- No setup (just enable)
- Automatically collects from other AWS services

**Weaknesses:**
- **AWS only** (no Azure/GCP)
- Complex UI (AWS console is messy)
- No multi-account dashboard
- No security score (just lists findings)
- No drift detection
- Overwhelming (thousands of findings, no prioritization)

**Why We Win:**
- **Multi-cloud:** AWS + Azure + GCP in one place
- **Simplicity:** One score vs thousands of findings
- **Multi-account:** Aggregate across all accounts
- **Better UX:** Modern dashboard vs AWS console

**Who They Win:**
- AWS-only shops
- Teams already deep in AWS ecosystem
- Companies with AWS support contracts

---

### 5. Lacework (Enterprise Competitor)

**Company Info:**
- **Founded:** 2015
- **Funding:** $1.3B raised
- **Employees:** 800+
- **HQ:** Mountain View, CA

**Product:**
- **What:** Cloud security platform with ML/AI
- **Price:** $50k-150k+/year
- **Clouds:** AWS, Azure, GCP
- **Key Features:**
  - Behavioral anomaly detection (AI/ML)
  - Cloud security posture management
  - Compliance automation
  - Container security

**Strengths:**
- AI/ML-powered anomaly detection
- Behavior baselines (learns normal patterns)
- Good for threat detection

**Weaknesses:**
- **Price:** $50k+ minimum
- Complex (AI blackbox)
- Requires security expertise
- Slow time-to-value (ML needs time to learn)

**Why We Win:**
- **Price:** 100x cheaper
- **Simplicity:** Clear checks vs AI blackbox
- **Speed:** Instant results vs ML training period

---

## Competitive Positioning Matrix

| Feature | CloudSecure | Wiz | Orca | Prowler | AWS Hub | Lacework |
|---------|-------------|-----|------|---------|---------|----------|
| **Price/year** | $1.2k-6k | $100k+ | $75k+ | Free | $1-5k | $50k+ |
| **Multi-cloud** | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| **Dashboard** | ✅ | ✅ | ✅ | ❌ | ⚠️ | ✅ |
| **Multi-account** | ✅ | ✅ | ✅ | ❌ | ⚠️ | ✅ |
| **Security Score** | ✅ (0-100) | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Drift Detection** | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| **Setup Time** | 5 min | Days | Days | 1 hour | 30 min | Days |
| **Target Customer** | Startups | Enterprise | Enterprise | DevOps | AWS-only | Enterprise |
| **Sales Model** | Self-serve | Sales-led | Sales-led | Self-serve | AWS | Sales-led |
| **Support** | Community | Enterprise | Enterprise | Community | AWS | Enterprise |

---

## Our Unique Differentiators

### 1. Security Credit Score (0-100)
**What it is:** One number that represents overall security posture  
**Why it matters:** 
- Board-ready metric
- Easy to track over time
- Gamifies security improvements
- No other tool does this

**Competitors:** All competitors show lists of findings, no single score

---

### 2. Startup-First Pricing
**What it is:** $99-499/month vs $50k-150k/year  
**Why it matters:**
- Seed/Series A can actually afford it
- No sales cycle (self-serve)
- Pay monthly, cancel anytime

**Competitors:** All enterprises require annual contracts

---

### 3. Open-Core Model
**What it is:** CLI stays free OSS, dashboard is paid  
**Why it matters:**
- Developers can try for free
- Build community + brand
- Upsell to dashboard when team grows

**Competitors:** Only Prowler is OSS (but no paid tier)

---

### 4. Drift Detection for Security
**What it is:** Track security score changes over time  
**Why it matters:**
- Prove improvements to investors
- Catch security regressions
- Historical trending

**Competitors:** Wiz/Orca have this, but $100k+

---

## Our Moat Strategy

### Short-term (6-12 months):
1. **Speed to market** - Launch before competitors notice segment
2. **Community** - Build OSS community around CLI
3. **Design partners** - Get testimonials from recognizable YC companies
4. **Content** - Own SEO for "startup security", "SOC 2 for startups"

### Medium-term (12-24 months):
1. **Compliance templates** - Pre-built SOC 2, ISO 27001, CIS mappings
2. **Remediation engine** - Auto-fix security issues
3. **Integrations** - Slack, PagerDuty, Jira
4. **Network effects** - Benchmark scores across all customers

### Long-term (24+ months):
1. **Data moat** - ML models trained on millions of scans
2. **Platform** - Become the security OS for startups
3. **Ecosystem** - Marketplace for custom checks/integrations
4. **Brand** - "The Stripe of cloud security" (developer-first)

---

## Competitive Objections & Responses

### "Why not just use AWS Security Hub?"
"Security Hub is AWS-only and shows thousands of findings with no prioritization. CloudSecure gives you one score (0-100) across AWS, Azure, and GCP. Plus multi-account aggregation."

### "Why not use Prowler for free?"
"Prowler is great for DevOps teams who love CLIs. CloudSecure adds a dashboard your CEO can understand, drift detection, and multi-account management. Our CLI is also open-source—we just charge for the value-add features."

### "Can't we just hire a security engineer?"
"A security engineer costs $150k-200k/year plus equity. CloudSecure costs $6k/year and runs 24/7. Use us until you're Series B and can afford a full security team."

### "Why not wait until we're bigger and use Wiz?"
"Wiz is amazing—for enterprises. But they require $100k+ minimum and a 6-month sales process. We're built for where you are NOW. When you hit Series C, upgrade to Wiz. We'll celebrate with you."

### "How do we know you won't shut down?"
 "Fair question. Our CLI is open-source MIT licensed—you can self-host forever. The dashboard is SaaS for convenience. Plus, we're building this as a venture-backable business."

---

## Competitive Win Strategy

### Against Wiz/Orca (Enterprise):
- **Win on price:** "We're 1/100th the cost"
- **Win on speed:** "Start scanning in 5 minutes"
- **Win on fit:** "Built for startups, not enterprises"

### Against Prowler (OSS):
- **Win on UX:** "Dashboard vs CLI"
- **Win on features:** "Drift detection, multi-account, credit score"
- **Win on support:** "Startup-friendly pricing, not free-but-alone"

### Against AWS Security Hub:
- **Win on multi-cloud:** "AWS + Azure + GCP in one place"
- **Win on UX:** "One score vs thousands of findings"
- **Win on aggregation:** "All accounts in one dashboard"

---

## Market Opportunity

### TAM (Total Addressable Market):
- **Startups:** ~50,000 seed-Series B companies globally
- **Average deal:** $300/month = $3,600/year
- **TAM:** $180M/year

### SAM (Serviceable Available Market):
- **Multi-cloud startups:** ~20,000 companies
- **Average deal:** $300/month
- **SAM:** $72M/year

### SOM (Serviceable Obtainable Market) - Year 1:
- **Target:** 100 paying customers
- **Average deal:** $200/month
- **SOM:** $240k ARR (achievable in 12 months)

---

## Next Steps

- [ ] Validate these assumptions in customer interviews
- [ ] Test messaging: "Security credit score" vs "Cloud security"
- [ ] Confirm pricing sensitivity ($99 vs $199 vs $499)
- [ ] Ask: "What would make you switch from Prowler/Security Hub?"