# Remote Consent Service Example

A 'Remote Consent Service' (aka 'RCS') is a service that can be interrogated as part of the OAuth2/OIDC flow where AM is the authorization server.
This project serves as a starting point for anyone attempting to implement their own Remote Consent Service that works together with Forgerock AM.

This remote consent service contains the following endpoints:

- ```GET /rest/rcs/jwks_uri``` - endpoint for returning the JWK set
- ```GET /rest/rcs/consent``` - load the page where the consent can be selected
- ```POST /rest/rcs/consent``` - save the consented claims/scopes and return a consent_response object back to OpenAM

This sample service also includes support for fetching data from the session. In this case, the RCS needs to receive the AM session cookie, which is used to call the AM instance to retrieve session properties. These properties will be displayed for any matching claim/scope, to show a user which data is concerned.

## How RCS Works
Once an RCS agent is added and configured as part of the OAuth2 provider settings (see configuration for details), AM will send the client a redirect towards this service. AM appends a request parameter called ```consent_request``` that contains a signed JWT (or signed-then-encrypted JWT, in case encryption is turned on) that this service validates and uses to build a 'Consent' page.

When the end user grants consent, a ```consent_response``` parameter is created with all the necessary details for AM. It is submitted to AM using a self-submitting form as an example.

Upon receiving the ```consent_response```, AM will determine whether it's encrypted or not. In case of encryption, AM uses the public key from either the ```JWKs_URI``` or the configured ```JWKs``` to decrypt the response. The signature of the received ```consent_response``` is also verified. When consent has been given by the end user, AM will proceed with its normal operations and save consent if so instructed (see '[OAuth2 Provider Configuration](oauth2-provider-configuration)')

This service deals with the consent as a 'Remote Consent Service'. This example implementation does not persist this anywhere other than in memory; other persistence implementations are left as an exercise.

# Configuration
## OpenAM Configuration

### Agent Configuration
AM needs to be configured with a 'Remote Consent' agent through 'Agents' -> 'Remote Consent' -> 'Add Remote Consent Agent'. On the screen that follows the following information can be provided:
- Agent ID - the name of the remote consent service (this name is also set as the 'audience' of the consent_request
- Remote Consent Service Secret - to be used if symmetric encryption is used
- JSON Web Key URI - the remote endpoint where AM will select the RSA public key from to use for decryption (as 'am.services.oauth2.remote.consent.response.decryption' inside AM)

Upon creating the 'Remote Consent Agent' the following fields should be configured:
- Redirect URL - set to <proto://rcs.domain.tld:8680/rest/rcs/consent>, depending on where you're running this remote consent service (defaults to http://localhost:8680)
- Enable Consent Encryption - set to ```true``` in case encryption of the ```consent_request``` parameter is desired
- Consent request Encryption Algorithm - currently only ```RSA-OAEP-256``` is supported by this service (others may follow in the future)
- Consent request Encryption Method - the value of this is also used as the encryption method in the returned ```consent_response```
- Consent request Signing Algorithm - set to ```RS256```
- Consent response encryption algorithm - set to the same value as 'Consent request Encryption Algorithm'
- Consent response encryption method - set to the same value as 'Consent request Encryption Method'
- Consent response signing algorithm - set to ```RS256```
- Public key selector - should be set to ```JWKs_URI``` when using this service for the JWK set
- Json Web Key URI - should be set to the URL on which this 'Remote Consent Service' is running. I.e. <proto://rcs.domain.tld:port/rest/rcs/jwks_uri>
- JWKs URI content cache timeout in ms - should only be changed when the keys rotate often, normally the defaults are fine 
- JWKs URI content cache miss cache time - should only be changed when the keys rotate often, normally the defaults are fine
- Json Web Key - can be used to enter a JWK set, only if 'Public key selector' is set to ```JWKs```

### OAuth2 Provider Configuration
The OAuth2 provider should be set up as usual, with 2 additions. On the 'Consent' page of the OAuth2 Provider configuration, the following settings need to be adjusted in order to invoke the Remote Consent Service:
- Enable Remote Consent - set to ```true``` in case Remote Consent is desired
- Remote Consent Service ID - set to the name of the previously created 'Remote Consent Agent'
- Save Consent Attribute - set this to a field under the user profile in case consent needs to be saved at the identity level

Additionally the setting for 'Allow Clients To Skip Consent' should be set to ```false``` to disable clients the ability to skip consent.

### Session Configuration
In case information from the AM session should be retrieved from AM, a method for setting these entries into the session need to be configured inside AM (i.e. a custom authentication module, a post-authentication processor, a scope validator, or a 'Set Session Properties' node inside an authentication tree.

To have RCS receive the cookie both AM and RCS need to use the same cookie domain, or else the browser will not forward the cookie to the RCS. Additional means of fetching the cookie are not included here.

#### Session Whitelist Configuration
By default AM does not allow anyone to retrieve session information. The only property that can be retrieved without additional configuration is the ```AMCtxId```. When different properties are requested, they need to be added to the 'Session Property Whitelist Service'. This service can be added in each realm through the 'Services' option. The configuration field for the 'Whitelisted Session Property Names' should contain the specific attribute that this RCS may need (which field that is depends on the specific environment). 
  

## RCS Configuration
### Generate Keystore
The setup requires a keystore to fetch information from. If you do not have an existing certificate that you want to use, a new keystore containing a self-signed certificate can be generated with a command like this:

```
$ keytool -genkeypair \
    -keysize 4096 \
    -validity 3650 \
    -sigalg SHA256withRSA \
    -keyalg RSA \
    -alias rcs_rsa \
    -storetype JKS \
    -storepass changeit \
    -keypass changeit \
    -keystore keystore.jks \
    -dname "CN=RCS, OU=Development, O=Booleans, L=Amersfoort, ST=UT, C=NL"
```
This is also how the included keystore was created. Replace this with your own!

### Remote Consent Configuration
The configuration of this Remote Consent Service is performed through java properties as an example.

A couple of settings are required to be able to run. The following properties are used:
- ```jwksUri``` - the JWKs URI endpoint where AM serves it's keys. For example: ```<proto://am.domain.tld:port/openam/oauth2/connect/jwk_uri>```
- ```keyAlias``` - the alias of the key that this Remote Consent Service should use to build its JWK set from
- ```keystorePath``` - path towards the keystore where the above alias can be found
- ```keyPass``` - password for the private key
- ```storePass``` - password for reading from the keystore
- ```encryptResponse``` - boolean to indicate whether the ```consent_response``` reply should be encrypted
- ```localIssuer``` - the name of this Remote Consent Service. Should be set to the same value as the name of the Agent as configured inside AM.
- ```useSessionData``` - boolean to indicate if an incoming session token from AM should be used to retrieve session details
- ```sessionService``` - URL pointing to an AM instance from where to get the session properties, for example: ```<proto://am.domain.tld:port/openam/json/sessions?_action=getSessionProperties>```
- ```cookieName``` - name of the session cookie as configured in AM. For example: ```iPlanetDirectoryPro```.

## Running RCS
For development purposes this includes an embedded Jetty setup which will spin up a new Jetty instance with this application deployed. To run the embedded Jetty use maven together with the maven-jetty plugin like this:

``` 
 $ mvn jetty:run
``` 
Although useful for development, this is not an option for any production deployment. To create a WAR file, run: 
```
 $ mvn package
```
## Configuration
This Remote Consent Service requires some information in order to run. These can be set with your normal JVM properties, or in case of the embedded Jetty through a MAVEN_OPTS setting:

```
 $ MAVEN_OPTS="${MAVEN_OPTS} -DkeyAlias=rcs_rsa -DjwksUri=http://am.domain.tld:port/openam/oauth2/connect/jwk_uri -DkeystorePath=keystore.jks -DkeyPass=changeit -DstorePass=changeit -DencryptResponse=true -DlocalIssuer=remote-consent-service -DcookieName=iPlanetDirectoryPro -DsessionService=http://am.domain.tld:port/openam/json/sessions?_action=getSessionProperties -DuseSessionData=true" mvn -o jetty:run
```

## Known Issues
 - The output pages look awful :)
 - The method for configuring this service is very crude and should be changed to fit your infrastructure/preferences.
 - Consent is stored in memory. A persistence implementation that fits your environment will have to be created. 
 - This sample does not support multiple private keypairs (one could reuse this RCS across different realms in AM, where different signing/encryption keys are likely to be preferred).
 - There's no support for multiple jwksUri's. Should not be very hard to add though.
 - There's no support for encrypting with EC keys in AM so this service focuses on RSA keys.
 - Symmetric encryption is not included.