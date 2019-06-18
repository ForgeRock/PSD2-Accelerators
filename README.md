# PSD2 Kits - OBIE Assets
This project contains several assets with the purpose of providing guidance for ASPSP’s seeking to implement the UK Open Banking Specification v3.1 using the ForgeRock Identity Platform™.

* **Forgerock Identity Gateway 6.5.1** – performs MTLS termination, SSA validation, access token validation (OAuth2 termination), performs authorization policies enforcement and evaluation in Forgerock Access Manager, API security
* **Forgerock Access Manager 6.5.1** – provides OIDC Dynamic Registration capabilities, OIDC Provider, Authentication & Authorization Provider including SCA
* **Forgerock Identity Manager 6.5** – stores consent and relationships between TPP and consent, manages the consent lifecycle.
* **Forgerock Directory Server 6.5.1** – stores user information, token persistence
* **Bank APIs & Consent UI** – resource server, UI for rich-consent authorization (debtor account selection).


## Contents
The high-level components that are included in this project:

#### AM
* **OAuth2 Provider Config**: OIDC configuration for Hybrid Flow and Client Credentials. Enable dynamic registration with SSA requirement
* **Authentication Tree**: Custom authentication tree handling the SCA exemptions and audit trails. 
* **Remote Consent Agent**: Remote Consent Agent configuration
* **Policy Definition**: Custom Policy Set and Resource Type for PISP and AISP
	
#### IG
* AM Route: Route to AM OIDC Dynamic Registration. Executes SSA Validation Filter with OB Directory
* Filter: JWTBuilderFilter Secrets Service
* Filter: Validate MTLS for resource access (token binding for the Authorization Server will be used from OOTB AM 6.5.1 capabilities)
* Filter: Validate SSA with Open Banking Directory
* Filter: Audit Filter (tppIdentifier + SSA)
* Route: /obie/v3.1/${resource}-consents . Generic route for consents
* Filter: Stateless OAuth Token Filter or Introspection Filter in AM for access tokens of authorization_code and client_credentials grant
* Filter: Validate Consent Objects to be valid from permission point of view
* Filter: Filter to provision authorization policy in AM per each consent resource
* Route: /obie/v3.1/${resource} . Generic route for resource access. Executes AM Authorization Policies Filter
* Filter: OAuth 2 Resource Server Authorization Service to AM
* Filter: eIDAS filter for header validation or client ssl profile (cn, ou)

#### IDM
* Managed Object: Managed Object for **TPP** and **SSA** (including relationship between them)
* Managed Object: Managed Object for **Payment Consent** (including relationship with the TPP and User managed objects)
* Managed Object: Managed Object for **Account Information Consent** (including relationship with the TPP and User managed objects)
	
#### RCS (Remote Consent Service)
* Sample frontend application developed in **React JS**
* Sample backend application developed in **Spring Boot** (including integration with AM and IDM APIs)
	
#### Mock RS (Bank Resource Server simulator)
* Sample **Spring Boot** application that simulates the Bank's mandatory APIs
	
#### Postman collection
* Postman project (both environment and configuration) that illustrates the all OBIE end2end flows 
	
	
## Usecases
The OBIE accelerators extend AM, IG and IDM to perform the following OBIE core functionalities:
* **MTLS Security Profile** (IG, AM) - [OBIE MTLS](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/83919096/Open+Banking+Security+Profile+-+Implementer+s+Draft+v1.1.2%23OpenBankingSecurityProfile-Implementer'sDraftv1.1.2-OAuth2.0,OIDCandFAPI)
* **SSA Validation with OB Directory Security Profile** (IG) - [OBIE SSA Validation & OIDC Dynamic Registration](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/937066600/Dynamic+Client+Registration+-+v3.1)
* **FAPI-RW Security Profile** (AM): [OBIE OIDC & FAPI](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/83919096/Open+Banking+Security+Profile+-+Implementer+s+Draft+v1.1.2%23OpenBankingSecurityProfile-Implementer'sDraftv1.1.2-OAuth2.0,OIDCandFAPI)
* **OIDC Dynamic Client Registration** (AM, IG, IDM) - [OBIE SSA Validation & OIDC Dynamic Registration](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/937066600/Dynamic+Client+Registration+-+v3.1)
* **OIDC Hybrid Flow Security Profile** (AM) - [OBIE OIDC & FAPI](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/83919096/Open+Banking+Security+Profile+-+Implementer+s+Draft+v1.1.2%23OpenBankingSecurityProfile-Implementer'sDraftv1.1.2-OAuth2.0,OIDCandFAPI)
* **SCA & Consent Security Profile** (AM, IG) - [OBIE AISP Consent](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/5785171/Account+and+Transaction+API+Specification+-+v1.1.0) ; [OBIE PISP Consent](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/5786479/Payment+Initiation+API+Specification+-+v1.1.0)
* **Consent Object Persistence**: PISP, AISP, CBPII (IDM, DS) - [OBIE AISP Consent](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/5785171/Account+and+Transaction+API+Specification+-+v1.1.0) ; [OBIE PISP Consent](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/5786479/Payment+Initiation+API+Specification+-+v1.1.0)
* **Consent Based Authorization Security Profile** (AM, IG) - [OBIE FAPI Authorization](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/641992418/Read+Write+Data+API+Specification+-+v3.0)


# AM Setup
> **Prerequisite**: In order these accelerators to work as designed, you will need the AM 6.5.1 version which contains support for setting up mTLS and can be downloaded here: [https://backstage.forgerock.com/downloads/browse/am/latest](https://backstage.forgerock.com/downloads/browse/am/latest). You'll need a valid Backstage subscription to get it.

## AM Configuration - Amster import /openbanking realm
**Amster** is a command-line interface built upon the ForgeRock Access Management REST interface. Amster can export all the configuration related to an AM realm, and import it back.
> Note that Amster only manages configuration data. User information in data stores is not imported or exported, or modified in any way.

The /openbanking AM Realm contains customizations for the following components:
* Applications -> Agents -> Java Agents: ig_agent (used inside the IG routes)
* Applications -> Agents -> Remote Consent: forgerock-rcs (contains the configuration for the RCS frontend application and you should change them accordingly: Redirect URL & Json Web Key URI. This rcs agent is included in the Oauth2 Provider configuration in the Remote Consent Service ID field)
* Applications -> Agents -> Software Publisher
* Applications -> OAuth 2.0: ig_agent_oauth2 (used inside the IG routes)
* Authentication -> Chains: openbanking (authentication chain username & password only)
* Authentication -> Trees: ob-auth-tree (authentication tree with additional OTP for SCA)
* Authorization -> Policy Sets -> AISP Authorization Policy 
* Authorization -> Policy Sets -> PISP Authorization Policy 
* Authorization -> Resource Types -> URL
* Scripts: openbanking (OIDC Claims script used in the Oauth2 Provider configuration)
* Services -> Base URL Source (used the Fixed Value of the IG environment)
* Services -> Oauth2 Provider (the OAuth2 & OIDM specific configuration according to the OpenBanking security specifications)

> The steps to follow in order to import the AM OBIE specific configuration are detailed in it's own README [OpenAM/amster-export/README.md](OpenAM/amster-export/README.md)

## AM Custom Scope Validator
This project implements a new custom scope validator that has the purpose of adding the open_banking_intent_id in the token and to be returned further in the /userinfo API output. The custom scope validator is added next to the OpenAM original features, without changing any of the out of the box source code.

Ensure that you have access to the ForgeRock maven repositories. This requires a backstage account which is associated with a ForgeRock subscription.
Detailed instructions for setting up maven repository access can be found here: [https://backstage.forgerock.com/knowledge/kb/article/a74096897](https://backstage.forgerock.com/knowledge/kb/article/a74096897)

> This asset comes with it's own README, please see [OpenAM/obie-openam-scope-validator/README.md](OpenAM/obie-openam-scope-validator/README.md)


# IG Setup
This project contains a number of custom java filters, routes and scripts for ForgeRock IG configurations.
	
The IG routes included in this project are:
* OBIE OpenAM Generic Route (proxy to AM for the following mathing rule: ^(/UI|/XUI|/json|/oauth2/realms/root/realms/openbanking/connect/jwk_uri))
* OBIE OpenAM Metadata (proxy to the /.well-known/openid-configuration AM endpoint - includes also a custom groovy script that is replacing, in the output response returned by AM, the base hostname in the case you want that specific endpoints to be used directly to AM and not through IG) 
* OBIE Assets OpenAM Authorize Route (proxy to the /authorize AM endpoint - contains a custom filter that validates the content of the input request JWT and a custom groovy script that converts the query parameters returned by AM in some error scenarios to fragment)
* OBIE Assets OpenAM Token Route (proxy  to the /access_token AM endpoint - contains a custom filter that checks the validity of the TPP transport certificate taken from a specific [configurable] header name)
* OBIE TPP Registration (proxy to the AM /register endpoint - calls also IDM, through a custom java filter, in order to create the TPP & SSA IDM managed objects; check the validity of the TPP client certificate taken from a specific [configurable] header name)
* OBIE Assets Account Consents Route (proxy to the IDM /openbanking/v3.1/account-access-consents endpoint - POST, GET and DELETE consent methods)
* OBIE Assets Accounts Resource Route (proxy to the RS /openbanking/v3.1/accounts endpoint - GET account list, GET account details, GET account balances, GET account transactions; enforces AM policy in order to validate the authorization)
* OBIE Assets Payment Consents Route (proxy to the IDM /openbanking/v3.1/domestic-payment-consents - POST and GET payment consent methods)
* OBIE Assets Payment Funds Confirmation Route (proxy to the RS /openbanking/v3.1/funds-confirmation GET endpoint - enforces AM policy in order to validate the authorization)
* OBIE Assets Payment Resource Route (proxy to the RS /openbanking/v3.1/domestic-payments endpoint - GET payment details method)
* OBIE Assets Payment Submission Route (proxy to the RS /openbanking/v3.1/domestic-payments endpoint - POST submit payment method - enforces AM policy in order to validate the authorization)
* OBIE RS Metadata (proxy to the RS metadata endpoint)
	
The scripts included in the IG package are:
* ConvertQueryToFragment.groovy
* ReplaceHostnamesASDiscovery.groovy


## Build and deploy custom java filters
> Please see the dedicated README for details on how to build and deploy these java assets: [OpenIG/openig-custom-obie-filters/README.md](OpenIG/openig-custom-obie-filters/README.md)

## IG Configuration 

### Routes and scripts
Before copying the configuration files (under /config location on the github repository, you should change accordingly all the URLs and credentials in order to match your environment needs:
* AM endpoint
* IG endpoint
* IDM endpoint
* Resource Server endpoint
* AM Introspect client credentials
* IDM admin credentials

Copy the content of the /config and /scripts folders to your IG /config and /scripts locations. By default, the IG configuration files are located in the directory `$HOME/.openig` (on Windows, `%appdata%\OpenIG`). 

### Secrets configuration
There are two types of configuration needed. First, a place where the secrets are stored inside the filesystem, for looking up secrets that are later used inside the keystore configuration.

```
  "secrets" : {
    "stores" : [ {
      "type" : "FileSystemSecretStore",
      "config" : {
        "format" : "PLAIN",
        "directory" : "${openig.baseDirectory.path}/secrets/obie"
      }
    } ]
  }
```

The configuration that points to the actual keystore looks somewhat like this:

```
	{
        "name" : "RetrieveSecretsFilter",
        "type" : "RetrieveSecretsFilter",
        "config" : {
          "directory" : "${openig.baseDirectory.path}/secrets/obie",
          "passwordSecretIds" : "igAgentOauth"
        }
    }
	
	...  
	
	"config" : {
	  "filters" : [ {
		"type" : "HeaderFilter",
		"config" : {
		  "messageType" : "request",
		  "add" : {
			"Authorization" : [ "Basic ${attributes.igAgentOauth}" ]
		  }
		}
	  } ],
	  "handler" : "ForgeRockClientHandler"
	}

```

#### Adding secrets
To make this work, the `FileSystemSecretStore` needs a file for each of the different `passwordSecretIds` values containing the plain value of the password and place them under the configured directory - ex. in this configuration: ${openig.baseDirectory.path}/secrets/obie 


## Setting up IG to terminate TLS
In order IG to be able to check the TPP client certificates with the filters and routes deliverd within this package, the content of the certificate should be passed through a HTTP Request Header. 
In our environment we have used the openig ingress component to forward the content of the client certificate in the specific ssl-client-cert HTTP header (we have created a secret store from the Openbanking Directory root and intermediate CA):

```
  annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/affinity: cookie
    nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream: "true"
    nginx.ingress.kubernetes.io/auth-tls-secret: psd2acceldemo/ob-ca
    nginx.ingress.kubernetes.io/auth-tls-verify-client: optional_no_ca
    nginx.ingress.kubernetes.io/auth-tls-verify-depth: "3"
    nginx.ingress.kubernetes.io/ssl-ciphers: ECDH+AESGCM:DHE+AESGCM
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
```



# IDM Setup
This project contains a number of custom endpoints, scripts and managed object configurations.

The managed objects included in the IDM configuration:
* ObTpp (contains the TPP details and, as identifiers we are storing the identifier from the SSA included in the registration request and also the client_id generated by AM after a successful registration)
* ObTppSsa (stores the SSA that came with the registration request)
* ObAccountAccess (stores the AISP intent objects having the definition according to the OBIE specifications)
* ObDomesticPayment (stores the PISP intent objects having the definition according to the OBIE specifications)

The custom endpoints included in the IDM package:
* endpoint-obAccountAccessIntent (custom endpoint that manages the AISP consent flows)
* endpoint-obPaymentIntent (custom endpoint that manages all the PISP consent scenarios)
* endpoint-obTpp (custom endpoint for the TPP registration flow)

The custom endpoints included in the IDM package:
* config.js (contains the configurable parameters used inside the all other scripts: AM server details, IDM server details, IG server details, Resource Server details, OBIE IDM Managed Objects, OBIE AM Policy Configs)
* fr_am_utils.js (contains definition of the AM specific methods for the policy creation)
* mainOBHandler.js (main script that is called from the custom endpoints and which then forwards the logic to the right script according to the current scenario)
* ob_account_access_intent.js (contains the logic related to the AISP consent methods)
* ob_am_policy.js (contains the logic which constructs the AISP & PISP policy details before submitting the requests to AM)
* ob_payment_intent.js (contains the logic related to the PISP consent methods)
* ob_rs_discovery.js (mock script for the RS metadata endpoint)
* ob_tpp.js (implementation for the creation of TPP objects)
* ob_utils.js (general util methods used in the all other scripts)

## Configuration, endpoints and scripts
Before copying the script files (under /script/obie location on the github repository, you should change accordingly all the properties inside config.js file).

Copy the content of the /conf and /script folders to your IDM /conf and /script locations.



# Necessary Services

## Remote Consent Service Sample
Project 'psd2obie_microservice' is a sample implementation of a Remote Consent Service. Configuring Remote Consent is documented in the official Forgerock documentation, see [https://backstage.forgerock.com/docs/am/6.5/oauth2-guide/#oauth2-implement-remote-consent](https://backstage.forgerock.com/docs/am/6.5/oauth2-guide/#oauth2-implement-remote-consent)

> This sample comes with it's own README, please see [Remote Oauth2 Consent Service/psd2obie_microservice/README.md](Remote Oauth2 Consent Service/psd2obie_microservice/README.md)


## Resource Server Mock
> There's a README included on how to run the sample bank simulator: [MockResourceServer/ForgerockREST/README.md](MockResourceServer/ForgerockREST/README.md)



# Troubleshooting

## Invalid Authentication Method
When an mTLS authentication is attemped and AM returns an error with 'Invalid authentication method for accessing this endpoint', then the used authentication method is not in line with how the OAuth2 client is configured.

For mTLS this needs to be set to `self_signed_tls_client_auth` in case of self-signed mTLS.

To fix this, navigate to the realm -> 'Applications' -> 'OAuth2' -> click on the client in question -> 'Advanced' and set the 'Token Endpoint Authentication Method' to the correct value.

## Requested Claims Must Be Allowed
When AM returns an error like this:
```
{
  "error_description": "Requested claims must be allowed by the client's configuration.",
  "error": "invalid_request"
}
```
The claim that was requested needs to be configured inside the 'Supported Claims' field for the 'OAuth2 Provider'. See the configuration section earlier.

## Scope validator class not found
When the scope validator class is configured inside the 'OAuth2 Provider' and an attempt to use it raises an error like 
```
http://www.example.com?error_description=Scope%20Validator%20class%20not%20found&state=456&error=server_error
```

There could be three reasons for this:
	- Configuration is not correct inside the 'OAuth2 Provider'
	- JAR is not available for AM
	- JAR is installed, but AM has not been restarted

In case of the JAR installation it needs to be copied into the ```WEB-INF/lib``` directory and the AM container has to be restarted to make this class available to AM.

## Invalid Scope
When a scope is requested but not preconfigured to be allowed, the following error might be returned: 
```
http://www.example.com?error_description=Unknown%2Finvalid%20scope%28s%29%3A%20%5Babc%5D&state=456&error=invalid_scope
```

AM does not allow scopes that are not configured. To configure additional scopes, navigate to the client in question and add the necessary scopes to the 'Scope(s)' field in the 'Core' tab of the client. 


# BUGS
We don't have a specific bugs list but most probably there are some open issues that can be found. We will continue testing the assets and come back with updates for the parts that we find being not 100% compliant with the OBIE specifications.

This has been originally created against version 6.5.1-RC2 that includes mTLS support. This has now been updated to point to the officially released version 6.5.1.


## License

This project is licensed under the Common Development and Distribution License (CDDL). The following text applies to 
both this file, and should also be included in all files in the project:

>  Copyright 2019 ForgeRock AS
>
> Licensed under the Apache License, Version 2.0 (the "License");
> you may not use this file except in compliance with the License.
> You may obtain a copy of the License at
>
>    http://www.apache.org/licenses/LICENSE-2.0
>
>  Unless required by applicable law or agreed to in writing, software
>  distributed under the License is distributed on an "AS IS" BASIS,
>  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
>  See the License for the specific language governing permissions and
>  limitations under the License.