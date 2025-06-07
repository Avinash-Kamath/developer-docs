---
title: Service Principals (Org-level Tokens)
sidebar:
  label: Service Principals
prev: false
---

**Enable your tenant organizations to create automated access to your APIs**

Service Principals provide organization-level authentication for your B2B SaaS platform, allowing tenant organizations to create automated systems that access your APIs on behalf of the entire organization. This guide shows you how to implement OAuth 2.1 Client Credentials flow for organization-level API access.

## What are Service Principals?

Service Principals are **organization-owned OAuth clients** that act on behalf of an entire tenant organization rather than individual users. They enable organizations to build automation, integrations, and workflows that access your APIs without requiring user interaction.

### Real-World Example: AcmeCRM Platform

**Your B2B SaaS:** AcmeCRM - customer relationship management platform  
**Tenant Organization:** BigCorp - enterprise customer using AcmeCRM  
**Use Case:** BigCorp wants their internal reporting tool to automatically pull customer data from AcmeCRM every morning

![Service Principal Flow](@/assets/docs/guides/m2m/service-principal-flow.png)

1. BigCorp admin logs into AcmeCRM and creates a Service Principal
2. AcmeCRM uses Scalekit API to create a Service Principal and issues `client_id` and `client_secret` scoped to BigCorp's organization
3. BigCorp configures their reporting tool with these credentials
4. Reporting tool uses acmecrm.scalekit.com's token endpoint to get an access token scoped to BigCorp's organization
5. Reporting tool uses this access token to access AcmeCRM's API
6. AcmeCRM validates the token and returns only BigCorp's organizational data based on the API Request.

## Step 1: Set Up Service Principal Creation in Your Application

### Prerequisites

- Scalekit environment configured for your B2B SaaS
- Admin interface in your application for organization management
- Understanding of your organization data model

### Add Service Principal Management to Your Admin UI

```javascript
// React component for organization admins
import React, { useState } from 'react';

const ServicePrincipalManager = ({ organizationId }) => {
  const [servicePrincipals, setServicePrincipals] = useState([]);
  const [isCreating, setIsCreating] = useState(false);

  const createServicePrincipal = async (formData) => {
    setIsCreating(true);
    try {
      // Call your backend API to create Service Principal via Scalekit
      const response = await fetch('/api/admin/service-principals', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          organization_id: organizationId,
          name: formData.name,
          description: formData.description,
          scopes: formData.scopes,
          expiry: formData.tokenLifetime
        })
      });
      
      const newServicePrincipal = await response.json();
      setServicePrincipals([...servicePrincipals, newServicePrincipal]);
      
      // Show credentials modal (one-time display)
      showCredentialsModal(newServicePrincipal);
    } catch (error) {
      console.error('Failed to create Service Principal:', error);
    } finally {
      setIsCreating(false);
    }
  };

  return (
    <div className="service-principal-manager">
      <h3>API Access for {organizationName}</h3>
      <p>Create Service Principals to enable your organization's systems to access our API automatically.</p>
      
      <ServicePrincipalForm onSubmit={createServicePrincipal} />
      <ServicePrincipalList principals={servicePrincipals} />
    </div>
  );
};
```

### Backend API for Service Principal Creation

```javascript
// Node.js Express endpoint
app.post('/api/admin/service-principals', authenticateOrgAdmin, async (req, res) => {
  try {
    const { organization_id, name, description, scopes, expiry } = req.body;
    
    // Verify admin has permission for this organization
    if (!canManageOrganization(req.user, organization_id)) {
      return res.status(403).json({ error: 'Insufficient permissions' });
    }
    
    // Create Service Principal via Scalekit
    const servicePrincipal = await scalekit.m2mClient.createOrganizationClient(
      organization_id,
      {
        name: `${name} (${organization_id})`,
        description: `${description} - Created by ${req.user.email}`,
        scopes: scopes,
        audience: [`api.yourcompany.com`],
        expiry: expiry || 3600,
        custom_claims: [
          { key: "organization_id", value: organization_id },
          { key: "created_by", value: req.user.id },
          { key: "client_type", value: "service_principal" }
        ]
      }
    );
    
    // Store reference in your database
    await db.servicePrincipals.create({
      client_id: servicePrincipal.client.client_id,
      organization_id: organization_id,
      name: name,
      description: description,
      scopes: scopes,
      created_by: req.user.id,
      created_at: new Date(),
      status: 'active'
    });
    
    // Return credentials (only shown once)
    res.json({
      client_id: servicePrincipal.client.client_id,
      client_secret: servicePrincipal.plain_secret, // Only returned here!
      name: name,
      scopes: scopes,
      created_at: servicePrincipal.client.create_time
    });
    
  } catch (error) {
    console.error('Service Principal creation failed:', error);
    res.status(500).json({ error: 'Failed to create Service Principal' });
  }
});
```

```python
# Python Flask endpoint
@app.route('/api/admin/service-principals', methods=['POST'])
@require_org_admin
def create_service_principal():
    data = request.get_json()
    organization_id = data['organization_id']
    
    # Verify admin permissions
    if not can_manage_organization(current_user, organization_id):
        return jsonify({'error': 'Insufficient permissions'}), 403
    
    try:
        # Create via Scalekit
        service_principal = scalekit.m2m_client.create_organization_client(
            organization_id=organization_id,
            name=f"{data['name']} ({organization_id})",
            description=f"{data['description']} - Created by {current_user.email}",
            scopes=data['scopes'],
            audience=['api.yourcompany.com'],
            expiry=data.get('expiry', 3600),
            custom_claims=[
                {'key': 'organization_id', 'value': organization_id},
                {'key': 'created_by', 'value': str(current_user.id)},
                {'key': 'client_type', 'value': 'service_principal'}
            ]
        )
        
        # Store in database
        db.session.add(ServicePrincipal(
            client_id=service_principal.client.client_id,
            organization_id=organization_id,
            name=data['name'],
            description=data['description'],
            scopes=data['scopes'],
            created_by=current_user.id
        ))
        db.session.commit()
        
        return jsonify({
            'client_id': service_principal.client.client_id,
            'client_secret': service_principal.plain_secret,
            'name': data['name'],
            'scopes': data['scopes'],
            'created_at': service_principal.client.create_time
        })
        
    except Exception as error:
        return jsonify({'error': 'Failed to create Service Principal'}), 500
```

### Organization Context in Tokens

When organizations use their Service Principal credentials, tokens automatically include organization context:

```json
{
  "client_id": "sp_org_bigcorp_reporting_tool",
  "exp": 1745305340,
  "iat": 1745218940,
  "iss": "https://your-env.scalekit.com",
  "jti": "tkn_69041163914445100",
  "nbf": 1745218940,
  "oid": "org_bigcorp_12345",
  "scopes": [
    "read:customers",
    "read:deals", 
    "read:analytics"
  ],
  "sub": "sp_org_bigcorp_reporting_tool",
  "custom_claims": {
    "organization_id": "org_bigcorp_12345",
    "created_by": "admin_user_456",
    "client_type": "service_principal"
  }
}
```

---

## Step 3: Implement Organization-Aware Token Validation

Whenever API calls are made to your API, validate the token as follows:

- Ensure that the token is valid by checking the signature using the public key found in your Scalekit JWKS endpoint. Your JWKS endpoint will be of the format:

```xml showLineNumbers=false
https://your-env.scalekit.com/keys
```

- Ensure that the token is not expired by checking the `exp` and `nbf` claims in the JWT token.
- Ensure that the token was issued by Scalekit by checking the `iss` claim in the JWT token.
- Ensure that the token was issued to your API by checking the `aud` claim in the JWT token.
- Ensure that the token is scoped to the organization by checking the `oid` claim in the JWT token.
- Ensure that the token has the required scopes by checking the `scopes` claim in the JWT token.

---

## Troubleshooting for Organizations

### Common Issues Organizations Face

**Issue: "invalid_client" Error**

```javascript
// Help organizations debug credential issues
const debugServicePrincipal = async (clientId, clientSecret) => {
  try {
    const response = await fetch('https://your-env.scalekit.com/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: clientId,
        client_secret: clientSecret
      })
    });
    
    if (!response.ok) {
      const error = await response.json();
      console.error('Authentication failed:', error);
      
      // Provide helpful error messages
      if (error.error === 'invalid_client') {
        console.log('💡 Check: Are your client_id and client_secret correct?');
        console.log('💡 Check: Was this Service Principal created in the correct organization?');
        console.log('💡 Check: Is the Service Principal still active?');
      }
    }
  } catch (error) {
    console.error('Network error:', error);
  }
};
```

**Issue: Organization Data Not Appearing**

```javascript
// Debug organization context issues
const debugOrganizationAccess = (token) => {
  const decoded = jwt.decode(token);
  console.log('Token organization context:');
  console.log('Organization ID:', decoded.oid);
  console.log('Custom claims:', decoded.custom_claims);
  console.log('Scopes:', decoded.scopes);
  
  if (!decoded.oid) {
    console.error('❌ Token missing organization context');
    console.log('💡 This may be an issue with Service Principal configuration');
  }
};
```

---

## Next Steps

✅ **Service Principals Implemented!** Your tenant organizations can now create automated API access.

**What's Next:**

1. **[Add Third-Party App Support](/guides/m2m/user-delegated-access/)** - Enable external developer integrations
2. **[Implement Advanced Scoping](/guides/m2m/scopes-permissions/)** - Design sophisticated permission models  

**For Your Organizations:**

- Provide clear documentation on Service Principal creation
- Set up monitoring and usage analytics  
- Establish credential rotation policies
- Create example integration code for common use cases
