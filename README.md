## Sparrow
Sparrow is an identity server based on SCIM v2 specification, OAuth2.0 and OpenIDConnect.
The goal is to support fast reads, domains and making schema handling simple and easy.
All the data is accessible over HTTP and authentication and authorization are supported by OpenIDConnect and OAuth2.

## Why Another Identity Server??
One motivation was to have a server that contains all the features of an LDAP server minus the pain of organizing and
maintaining the Schema.
Also (IMHO), LDAP's authorization model based on ACIs is very brittle, which brings to my another thought of having a 
fluent access control(ARBAC) mechanism built right into the identity server.
And I want an identity server to have the ability to speak over HTTP directly without the need of custom proxies. 

## What Features are Available Right Now?
1. All the SCIM v2 features (except for /Bulk and /Me) are implemented
2. RBAC0 is supported
3. Support for OAuth2.0 and OpenIDConnect
4. Support for multiple domains
5. A java client, see https://github.com/keydap/sparrow-client 
6. Support for LDAP bind, unbind, search and password modify operations over startTLS.

## Can I Use it in Production Environment?
Not yet. We are aiming to make it production ready by Q4 2017.
 
## What is Happening Right Now?
1. Preparing for OpenIDConnect Certification

## Building and Running
1. git checkout https://github.com/keydap/sparrow.git
2. cd sparrow
3. ./build-release.sh
4. The binaries will be available under "dist" folder

## License
Sparrow is licensed under [Apache License Version 2](http://apache.org/licenses/LICENSE-2.0.txt)

Copyright 2017 Keydap Software.
