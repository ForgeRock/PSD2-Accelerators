# YES Capabilities

This project contains several classes to assist in setting up AM to be used with a YES.com integration.

## Contents
The following items are included in this project:

- Custom authentication node for use inside an Authentication Tree
- Custom error message node for use inside an Authentication Tree
- Custom scope validator for use inside an OAuth2 Provider
- Custom plugin logic to retrieve Verified Person Data from a remote endpoint
- Custom IG route configuration for use inside OpenIG
- Custom groovy scripts for use inside OpenIG
- Demonstration scripts
- Sample mock services

## Usecases
The artifacts extend AM and IG to perform the following tasks:

- get verified person data from a remote service to return in a userinfo call
- allow dynamic scopes, for example ```https://www.yes.com/scopes/pis:1234566``` where the value after the scope name is a dynamic value
- custom error handling in case of incompatible default errors
- custom error handling in case of incorrect values
- sending mediation records in case of an issued access_token or a userinfo response

## AM Artifact
Because the official release containing the mTLS setup is not yet released as version 6.5.1, there's also a version of AM included (release candidate 2) which can be found here: [artifacts/AM-6.5.1-RC2.war](artifacts/AM-6.5.1-RC2.war)

## Building
Ensure that you have access to the ForgeRock maven repositories. This requires a backstage account which is associated with a ForgeRock subscription.

Detailed instructions for setting up maven repository access can be found here: [https://backstage.forgerock.com/knowledge/kb/article/a74096897](https://backstage.forgerock.com/knowledge/kb/article/a74096897)

Once setup, run maven to build a JAR:
```
 $ mvn clean install
```

Once the build has succeeded, the JAR is in the ```target/``` directory and can be copied to an AM instance for installation.

## Installation
The JAR that was built needs to be available to the OpenAM instance. Place a copy of the JAR into the unpacked deployed application under your Tomcat's webapps directory, in the ```WEB-INF/lib``` folder. AM will need to be restarted after installation.

## Configuration

### mTLS Setup
This section is included here but is obsolete once the official Forgerock documentation for this feature has been published (expected as part of the 6.5.1 release). In the mean time, this is how to enable mTLS support as per the [draft mTLS spec](https://tools.ietf.org/html/draft-ietf-oauth-mtls-13).

#### Tomcat Setup
In this document we assume that Tomcat is used as the container of choice for the AM deployment. The configuration outlined here also assumes the tomcat-native library to be installed and available in the Tomcat library path.

This example uses self-signed certificates for the setup and assumes that TLS terminates at the AM container. If TLS termination is handled elsewhere, the client certificate should be added to a header in the forwarded request towards AM.

Generating a self-signed server certificate:

```
$ openssl ecparam -name prime256v1 -genkey -noout -out mylocal.key
$ openssl req -new -x509 -key mylocal.key -out mylocal.crt -days 3650 -subj '/CN=name-inside-certificate'
```
This certificate should be made available to Tomcat in for example the ```conf/``` directory.

Then, setup the Tomcat SSL connector with a configuration similar to this:
```
<Connector port="8443" protocol="org.apache.coyote.http11.Http11AprProtocol"
        maxThreads="150" SSLEnabled="true" scheme="https" secure="true">
        <SSLHostConfig certificateVerification="optionalNoCA"
		caCertificateFile="conf/mylocal.crt"
		protocols="TLSv1.2"
		honorCipherOrder="true"
		ciphers="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384,TLS_ECDH_RSA_WITH_AES_256_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
256,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDH_RSA_WITH_AES_128_CBC_SHA,TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA">
            <Certificate certificateFile="conf/mylocal.crt"
                certificateKeyFile="conf/mylocal.key"
                certificateKeyPassword="changeit"
                type="EC"/>
        </SSLHostConfig>
    </Connector>
```
Now that the SSL listener is enabled, the OAuth2 client can be configured with the necessary settings.

#### OAuth2 Client Setup For mTLS
The configuration that needs to change in order to use mTLS client authentication are the following:

##### Advanced
Field 'Token Endpoint Authentication Method'. Needs to be set to ```self_signed_client_cert``` in this example.

##### Signing and Encryption
Field 'Public key selector' can be set to JWKs or JWKs_URI. In this sample we'll set it to 'JWKs'.

Setting this instructs AM to look at the 'Json Web Key' field to determine the key information. This field needs a JWKSet format (see [https://tools.ietf.org/html/rfc7517#page-10](https://tools.ietf.org/html/rfc7517#page-10) for details). An example JWKSet may look something like this:

```
{
  "keys": [
    {
      "kty": "EC",
      "x5t#S256": "6pchPaWNLoQ7ecKMD_26x727NcM70ShHIcpkTE_X41o",
      "x5t": "ydBHeiDgGy4FPOmcyWcl5QmLIj4",
      "crv": "P-256",
      "kid": "9f:c3:f4:c6:fb:a8:8b:06",
      "x5c": [
        "MIIBdjCCAR2gAwIBAgIJAJ/D9Mb7qIsGMAoGCCqGSM49BAMCMBgxFjAUBgNVBAMMDW9hdXRoMl9jbGllbnQwHhcNMTkwMTA4MTI0NTQ3WhcNMjkwMTA1MTI0NTQ3WjAYMRYwFAYDVQQDDA1vYXV0aDJfY2xpZW50MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMIkbTTF40jaAEvqJjnOR4oB8H+I5Si8LwL9w30btXZDPCyPz6kgB5ppW695CXtc+EN7fUT/powOJAyIXUmAIiaNQME4wHQYDVR0OBBYEFLO/qOh6iwy7S7Bv7K+9JskUUmcAMB8GA1UdIwQYMBaAFLO/qOh6iwy7S7Bv7K+9JskUUmcAMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgRBH3xymvRGJB4Ef782ooRJxToicNQ8pBYoJUMQjxdOgCIG7E1Nndighw7R8XMU1ZKUtZWJRnrgpFDcjdCZaxyXSP"
      ],
      "x": "MIkbTTF40jaAEvqJjnOR4oB8H-I5Si8LwL9w30btXZA",
      "y": "zwsj8-pIAeaaVuveQl7XPhDe31E_6aMDiQMiF1JgCIk",
      "alg": "ES256"
    }
  ]
}
```
We have created a small utility for this to help generating a JWKSet from a certificate. This utility can be found here: [https://bitbucket.org/booleans-nl/jwkset-generator](https://bitbucket.org/booleans-nl/jwkset-generator).

Field 'mTLS Self-Signed Certificate' holds the certificate itself (see the ```x5c``` field in the above JWK set).

Select 'Use Certificate-Bound Access Tokens' for added security, this adds a SHA-256 hash of the client certificate to the access_token. This only works when the OAuth2 Provider setting (located at the realm level under 'Services' -> 'OAuth2 Provider' and go to the 'Advanced' tab - there is a setting called 'Support TLS Certificate-Bound Access Tokens' that needs to be enabled).

#### Setup mTLS with HTTP Header
When TLS is terminated elsewhere, the OAuth2 Provider can be configured to look at a header for retrieving the client certificate for authentication.

This setting can be found by navigating to the realm and go to 'Services' -> 'OAuth2 Provider'. On the 'Advanced' tab there's a setting for 'Trusted TLS Client Certificate Header'. Its recommended to give this a random name.

Once configured, mTLS client authentication can also be performed over HTTP using the header as a request header.


### Scope Validator Configuration
#### OAuth2 Provider
To use the custom Verified Person Data Scope Validator inside an OAuth2 provider, navigate to the realm in question and go to 'Services' -> 'OAuth2 Provider' and edit the 'Advanced' tab to update the field 'Scope Implementation Class' with the class name for this plugin.

In this case it should be changed from ```org.forgerock.openam.oauth2.OpenAMScopeValidator``` to ```org.forgerock.openam.oauth2.VerifiedPersonScopeValidator```.

This enables the use of this custom scope validator.

The configuration for this scope validator can be performed in two places:

#### Configuration Through Authentication Node
Once the realm in which the 'Verified Person Data Scope Validator' is used, has a configured instance of the 'Verified Person Data Node', the configuration can be retrieved from there. This configuration is primarily used by the authentication node itself to store the Verified Person Data inside the session; but when the executed request does not contain a session, the 'Verified Person Data Scope Validator' has a fallback to communicate with the 'Verified Person Data' service by itself.

#### Configuration Through Advanced Properties
AM does not have configuration fields for a per-realm configuration of a custom scope validator. To enable this per realm configuration when the 'Verified Person Data Node' is not used, an additional advanced server property can be added to ensure that the 'Verified Person Data Scope Validator' can retrieve this information.

To add the configuration, navigate to 'Configure' -> 'Server Defaults' and click on 'Advanced'. Add a new property with name 'org.forgerock.openam.oauth2.VerifiedPersonDataConfig'. As its value it requires JSON under a key that matches the realm name with each setting defined as an array.

A sample configuration for realm with name "realm1" might look like this:

```
{
  "/realm1": {
    "readTimeout": [
      5
    ],
    "connectTimeout": [
      5
    ],
    "remoteVPDService": [
      "http://localhost:8789/rest/vpd/get_verified_person_data"
    ],
    "pluginClass": [
      "org.forgerock.openam.oauth2.yes.plugins.VerifiedPersonDataPlugin"
    ],
    "debugEnabled": [
      false
    ],
    "httpMethod": [
      "POST"
    ],
    "authMethod": [
      "NONE"
    ]
  }
}
```
Once this is added, click on the '+' next to this field to add it to the list of advanced properties, followed by 'Save Changes'. 

N.B. this step is not needed when a configure 'Verified Person Data Node' is active inside the same realm, that configuration will be used instead.

### Authentication Node Setup
#### Verified Person Data Node
When an Authentication Tree is used, the 'Verified Person Data Node' can be used to retrieve information from the remote Verified Person Data service and store it inside the session. To configure this node, add it to an authentication tree by navigating to the realm -> 'Authentication' -> 'Authentication Trees'. There a custom tree can be created or expanded.

Once the Verified Person Data Node is part of a tree, the following items can be configured:

- Node name: display name
- Verified Person Data Plugin Class: the name of the class that executes the call towards the remote Verified Person Data service
- URI of remote VPD Service: the URL where the 'Verified Person Data' can be collected.
- HTTP method to use: sets the HTTP method corresponding to what the remote Verified Person Data service.
- Connection timeout: the number of seconds to wait for a connection to be setup succesfully.
- Read timeout: the number of seconds to wait for a response from the remote Verified Person Data service.
- Authentication method: a placeholder for setting the authentication method to use when communicating with the remote Verified Person Data service. This is currently not being used but its value is injected into the configuration for the remote call (so it can be used by implementing your own plugin, see the section on 'Extending'

#### Custom Error Message Node
The Custom Error Message node can be used to redirect a previously detected erroneous situation towards the Relying Party.

There are two configuration properties:

- error: naming of the error, for example ```invalid_request```
- error_description: associated description, for example ```The request is invalid```

The Custom Error Message Node should be configured as a node that is connected to the failure state of a previous node as shown here:

![](custom-error-node.png)

### Restart AM
After all the configuration steps and library installations are completed, a restart of the container in which AM is deployed is required.

<include rest of the documentation for the other requirements!>

## Extending
The communication with a Verified Person Data service is not a standard one, so there is a method of implementing your custom logic to communicate with such a remote service. To do so, implement interface ```org.forgerock.openam.oauth2.yes.plugins.ClaimMapperPlugin``` and make this plugin available to AM.

Once your custom class is available it needs to be configured as well inside the Authentication Node for Verified Person Data to point to that class.

A sample implementation is also included in ```org.forgerock.openam.oauth2.yes.plugins.VerifiedPersonDataPlugin```.

## Necessary Services
In the ```mock-services/``` directory there are a couple of example services that could be used as a starting point for integration into an existing infrastructure.

### Remote Consent Service Sample
Project 'fr-remote-consent-service-sample' is a sample implementation of a Remote Consent Service. Configuring Remote Consent is documented in the official Forgerock documentation, see https://backstage.forgerock.com/docs/am/6.5/oauth2-guide/#oauth2-implement-remote-consent

This sample comes with it's own README, please see [mock-services/fr-remote-consent-service-sample/README.md](mock-services/fr-remote-consent-service-sample/README.md)

### Verified Person Data Mock
Directory 'yes-verified-person-data-mock' is a very simple jersey implementation that always returns the same data. It should only be used for a very basic test; the services that provide this data in real life are subject to strict rules for exposing this data.

There's a README included on how to run the sample: [mock-services/yes-verified-person-data-mock/README.md](mock-services/yes-verified-person-data-mock/README.md)

### Mediation Service Mock
At several points inside the flow the YES.com integration needs to record mediation data to a centralized endpoint. This mock is only a very, very basic jersey implementation that simply logs incoming records to STDOUT.

See the README for details on how to run it: [mock-services/yes-mediation-records-mock/README.md](mock-services/yes-mediation-records-mock/README.md)

## TODO
<include other documentation>

# BUGS
Probably. The spec is unclear about actual responses so it could very well be that not all of it is working correctly. While developing we did not have access to any environment suitable for testing the end-to-end flow.

This has been created against version 6.5.0.1 of AM and tested against a 7.0.0-SNAPSHOT version that includes mTLS support. When the next version (6.5.1 is due shortly at the time of writing) is released there could be some rework needed to adhere to API changes inside AM and an update of the ```pom.xml``` to point to the correct version.
