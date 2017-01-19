## Sparrow
Sparrow is an identity server based on SCIM v2 specification, JWT and OAuth2.0.
The goal is to support fast reads, domains and ARBAC.
All the data is accessible over HTTP and authentication and authorization are supported by OpenIdConnect2 and OAuth2.

## Why another identity server??
One motivation was to have a server that contains all the features of an LDAP server minus the pain of organizing and
maintaining the Schema.
Also, IMHO, LDAP's authorization model based on ACIs is very brittle, which brings to my another thought of having a 
fluent access control(ARBAC) mechanism built right into the identity server.
And I want an identity server to have the ability to speak over HTTP directly without the need of custom proxies. 

## What features are available right now?
1. All the SCIM v2 features (except for /Bulk and /Me) are implemented.
2. RBAC0 is supported
3. Support for JWT. User's authorization data is included in tokens after authentication.
4. Domains are supported
5. A client written is Java is opensourced, see https://github.com/keydap/sparrow-client 

## What is happening right now
1. Working on implementing support for LDAP bind and search operations
