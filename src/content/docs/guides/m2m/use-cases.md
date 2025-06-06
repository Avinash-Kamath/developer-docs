---
title: Use Cases Guide
sidebar:
  label: Use Cases
---

**Choose the right authentication pattern for your B2B SaaS platform**

As a B2B SaaS provider, you need to offer secure API access to different types of consumers. This guide helps you quickly identify which authentication pattern fits your specific needs.

## Quick Decision Guide

**Answer these questions to identify your primary use case:**

1. **Who needs to access your API?**
   - Your tenant organizations' internal systems → **Service Principals**
   - External developers building apps for your platform → **Third-Party Apps**  
   - Your own microservices communicating internally → **Microservices**

2. **Do you need user consent in the flow?**
   - No, organizational or system-level access → **Service Principals** or **Microservices**
   - Yes, users must grant permission to third-party apps → **Third-Party Apps**

3. **Where will the integration run?**
   - Your customers' infrastructure → **Service Principals**
   - External developers' applications → **Third-Party Apps**
   - Your own infrastructure → **Microservices**

---

## Use Case 1: Service Principals (Org-level Tokens)

**Your tenant organizations need automated access to your APIs for their internal systems.**

### When Your Customers Need Service Principals

- Business Intelligence & reporting tools
- ERP system integrations
- Compliance automation & data exports
- Internal dashboards & monitoring
- Backup & data archival systems

### Key Characteristics

- **Organization-level access** - tokens represent the entire tenant organization
- **No user consent required** - admins create credentials for organizational use
- **Data isolation** - automatic scoping to organization's data only
- **Long-running automation** - designed for persistent organizational systems

### Real-World Example

**Your Platform:** AcmeCRM  
**Customer:** BigCorp using AcmeCRM  
**Need:** BigCorp's Tableau integration pulls customer data daily for executive dashboards

BigCorp admin creates a Service Principal in AcmeCRM → Gets `client_id`/`client_secret` → Configures Tableau → Tableau uses Client Credentials flow → AcmeCRM returns only BigCorp's customer data

**👉 [Implement Service Principals](/guides/m2m/service-principals/)**

---

## Use Case 2: Third-Party Applications (User-delegated Access)

**External developers build applications that access your platform on behalf of your users.**

### When You Want Third-Party Developer Ecosystem

- Partner integrations (marketing tools, analytics)
- Mobile apps built by external developers
- Customer automation tools (Zapier-style)
- Marketplace apps & plugin ecosystems
- Integration platforms & custom solutions

### Key Characteristics

- **User consent required** - individual users explicitly grant permission
- **User-scoped access** - tokens tied to specific user accounts
- **External developers** - code runs outside your infrastructure
- **Revocable permissions** - users can revoke access anytime

### Real-World Example

**Your Platform:** EmailFlow  
**Third-Party:** AnalyticsPro  
**Need:** AnalyticsPro builds analytics dashboards for EmailFlow users

AnalyticsPro registers app → User clicks "Connect EmailFlow" → OAuth consent flow → User grants permissions → AnalyticsPro gets user-scoped access token → Can analyze that user's campaigns only

**👉 [Implement Third-Party Apps](/guides/m2m/user-delegated-access/)**

---

## Use Case 3: Microservices (Service-to-Service)

**Your own microservices need to authenticate with each other securely.**

### When Your Platform Needs Internal Service Auth

- API Gateway to backend services
- Service mesh communication (Istio, Linkerd)
- Event-driven architecture with secure messaging
- Zero-trust network security
- Database access control per service

### Key Characteristics

- **High-throughput requirements** - thousands of requests per second
- **Short-lived tokens** - frequently rotated (5-15 minutes)
- **Internal network only** - communication within your infrastructure
- **Service identity** - each service has unique credentials

### Real-World Example

**Your Platform:** CommerceHub  
**Architecture:** API Gateway + User Service + Order Service + Payment Service  
**Need:** Gateway authenticates all calls to backend services

Each service gets credentials → Gateway caches tokens → Uses Bearer tokens for all internal API calls → Services validate tokens via JWKS → Zero-trust internal communication

**👉 [Implement Microservices Authentication](/guides/m2m/microservices/)**

---

## Implementation Strategy

Most B2B SaaS platforms implement multiple patterns as they evolve:

### **Recommended Progression:**

**Phase 1: Foundation** → Start with **Microservices** to secure internal architecture

**Phase 2: Customer Value** → Add **Service Principals** to enable customer automation and API revenue

**Phase 3: Platform Growth** → Add **Third-Party Apps** to create ecosystem effects and partner integrations

### **Decision Matrix:**

| Factor | Service Principals | Third-Party Apps | Microservices |
|--------|-------------------|------------------|---------------|
| **Target Users** | Your customers | External developers | Your services |
| **User Consent** | Not required | Required | Not required |
| **Data Access** | Organization-scoped | User-scoped | Service-scoped |
| **Business Value** | Customer enablement | Platform ecosystem | Internal security |
| **Implementation Effort** | Medium | High | Low-Medium |

---

## Next Steps

**Ready to implement?** Choose your starting point:

1. **[Service Principals Guide](/guides/m2m/service-principals/)** - Enable customer automation (most common starting point)
2. **[User Delegated Access Guide](/guides/m2m/user-delegated-access/)** - Build developer ecosystem  
3. **[Microservices Guide](/guides/m2m/microservices/)** - Secure internal services

**Need the big picture first?** Read our [comprehensive overview](/guides/m2m/overview/) to understand how OAuth 2.1 fits into your B2B SaaS architecture.

**Still not sure?** Most teams start with **Service Principals** since it directly enables customer use cases and generates API revenue.
