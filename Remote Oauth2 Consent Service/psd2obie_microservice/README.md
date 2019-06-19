# Remote Consent Service Example

A 'Remote Consent Service' (aka 'RCS') is a service that can be interrogated as part of the OAuth2/OIDC flow where AM is the authorization server.
This project serves as a starting point for anyone attempting to implement their own Remote Consent Service that works together with Forgerock AM.

This remote consent service contains the following sub-components:

* **Fronted**: developed in React
* **Backend**: developed in Spring Boot

Backend consent service contains the following endpoints:

* ```GET /api/rcs/consent/jwk_pub``` - endpoint for returning the JWK set
* ```GET /api/rcs/consent``` - load the page where the consent can be selected
* ```POST /api/rcs/consent/sendconsent``` - update the consented claims/scopes in IDM and return a consent_response object back to OpenAM

This sample service also includes support for fetching data from the session. In this case, the RCS needs to receive the AM session cookie, which is used to call the AM instance to retrieve session properties. These properties will be displayed for any matching claim/scope, to show a user which data is concerned.


## How RCS Works
Once an RCS agent is added and configured as part of the OAuth2 provider settings (see configuration for details), AM will send the client a redirect towards this service. AM appends a request parameter called ```consent_request``` that contains a signed JWT (or signed-then-encrypted JWT, in case encryption is turned on) that this service validates and uses to build a 'Consent' page.

When the end user grants consent, a ```consent_response``` parameter is created with all the necessary details for AM. It is submitted to AM using a self-submitting form as an example.

Upon receiving the ```consent_response```, AM will determine whether it's encrypted or not. In case of encryption, AM uses the public key from either the ```JWKs_URI``` or the configured ```JWKs``` to decrypt the response. The signature of the received ```consent_response``` is also verified. When consent has been given by the end user, AM will proceed with its normal operations and save consent if so instructed (see '[OAuth2 Provider Configuration](oauth2-provider-configuration)')

## Backend Configuration
For some configuration you can change file for project at path:
*src/main/resources/config/application.yml*
* **issuerID: forgerock-rcs** - Sets the issuer (iss) claim.    
* **am-cookie-name: iPlanetDirectoryPro**- Cookie Name to successfully send JWT consent to and get access code.
* **am-jwk-url: ${rsc-remote-host.am}/oauth2/realms/root/realms/openbanking/connect/jwk_uri** - URI to read public key to check key and decryption
* **idm-get-payment-intent-consent-url: ${rsc-remote-host.idm}/openidm/managed/ObDomesticPayment/** - this will point to IDM application, it’s using to get payment Intent
* **idm-update-payment-consent-url: ${rsc-remote-host.idm}/openidm/endpoint/obPaymentIntent/** - this will point to IDM application, it’s using to update  payment Intent
* **idm-get-account-intent-consent-url: ${rsc-remote-host.idm}/openidm/managed/ObAccountAccess/** - this will point to IDM application, it’s using to get Consent ID 
* **idm-update-account-consent-url: ${rsc-remote-host.idm}/openidm/endpoint/obAccountAccessIntent/** -this will point to IDM application, it’s using to update Consent ID     
* **am-jwk-url-connect-timeout: 100** - Connection timeout after try to get JWK from AM
* **am-jwk-url-read-timeout: 100** - Read timeout after try to get JWK from AM
* **am-jwk-url-size-limit: 100000** - Size limit at trying to get JWK from AM
* **am-host-url: ${rsc-remote-host.am}** - AM url host an port
* **am-get-cookie-token: ${rsc-remote-host.am}/json/realms/root/realms/openbanking/authenticate** - try to get cookie from AM
* **idm-consent-status-authorised : Authorised** - Status matched in IDM
* **idm-consent-status-rejected : Rejected** - Status matched in IDM
* **idm-consent-status-awaiting : AwaitingAuthorisation** - Status matched in IDM    
* **sca-time-auto-accept: 90** - Time in day if consent is Authorized but not Expired, consent will be auto accepted
* **sca-time-expire: 180** - Time in day if consent passed  180 day and is Authorized and Expired
	

### Application for test environment	"application-test.yml"
* rsc-remote-host    
    - **am: https://login.psd2acceldemo.fridam.aeet-forgerock.com**  -  this will point to AM application, it’s using to get JWK’s from URI. Note should use format protocol://address:{port}/openam
    - **idm: https://openidm.psd2acceldemo.fridam.aeet-forgerock.com** - this will point to IDM application, it’s using to get/update Consent ID or payment Intent

* application
    - **idm-header-username: admin** - This property will use in the header to access IDM resource at POST retrieve/update
    - **idm-header-password: admin** - This property will use in the header to access IDM resource at POST retrieve/update
    - **accounts-endpoint: http://obie-rcs-mocks.psd2acceldemo.svc.cluster.local:8089/accounts/** - Use for retrieve Account information from core banking, using OBIE spec format.
	
### Deploy & Run

#### Local 
* Create war 
	```mvn clean install -DskipTests -Pdev```
* Run application 
	```mvn spring-boot:run -Pdev```

#### Test Deploy
* Run in terminal/ecliplse maven
	```mvn clean install -DskipTests -Ptest```

* kill  process 
	```ps -ef | grep psd-2-rsc-sevice-0.0.1-SNAPSHOT```
	
#### Run on different environment 
* Run application 
	```./psd-2-rsc-sevice-0.0.1-SNAPSHOT.war``` 

* Or create a script file (startOBAsset.sh) and add line
	```cd /path_to_war_location/OBIE_Asset && nohup ./psd-2-rsc-sevice-0.0.1-SNAPSHOT.war &```

* Access and copy all from this page **{ENV}/api/rcs/consent/jwk_pub**
	- Eg. https://obie-rcs-backend.psd2acceldemo.fridam.aeet-forgerock.com/api/rcs/consent/jwk_pub

* Access openAM **{ENV}/XUI/#realms/%2Fopenbanking/applications-agents-remoteConsent/agents/edit/forgerock-rcs**
 	 - Eg. https://login.psd2acceldemo.fridam.aeet-forgerock.com/XUI/#realms/%2Fopenbanking/applications-agents-remoteConsent/agents/edit/forgerock-rcs
* Or navigate to
	 - OpenAm (login with admin) -> realms (openbanking) - > Applications -> Agents -> Remote Consent -> agents 
	 - In  Public key selector  : JWKs (should be value)
	 - In Json Web Key : {"keys":[{"kty".....
	 - Save.
* Or you could use uri where AM is reading key from specific url.
	 - In  Public key selector : JWKs_URI
	 - Json Web Key URI : https://obie-rcs-backend.psd2acceldemo.fridam.aeet-forgerock.com/api/rcs/consent/jwk_pub
	 - Save and restart the AM application to use new keys from remote jwk uri.

#### Docker	script example
```
#!/bin/sh

echo "Enter deployment directory '/path_to_backend/devops/deployments/obie-rcs-backend'"
cd /path_to_backend/devops/deployments/obie-rcs-backend

echo "Building docker image 'obie-rcs-backend:1.0 .'"
sudo docker build -t obie-rcs-backend:1.0 .

echo "Tag docker to match external repository 'gcr.io/partner-portal-223015/obie-rcs-backend:1.0'"
sudo docker tag obie-rcs-backend:1.0 gcr.io/partner-portal-223015/obie-rcs-backend:1.0

echo "Push docker image to Google Container Registry 'gcr.io/partner-portal-223015/obie-rcs-backend:1.0'"
sudo gcloud docker -- push gcr.io/partner-portal-223015/obie-rcs-backend:1.0

echo "Deploy obie-rcs-backend to Google Cloud Kubernetes Engine"
sudo kubectl delete -f obie-rcs-backend-deployment.yaml
sudo kubectl apply -f obie-rcs-backend-deployment.yaml
```


## Frontend Configuration
For some configuration you can change file for project at path:
*/psd2-obie-frontend/.env.cloud*

**REACT_APP_API_URL=https://obie-rcs-frontend.psd2acceldemo.fridam.aeet-forgerock.com** - URL to request microservice
**HOST=https://obie-rcs-frontend.psd2acceldemo.fridam.aeet-forgerock.com** - URL to request microservice


### Deploy & Run

#### Local 	
* Run application
	```yarn start```

#### Test Deploy
* create a build for 
	```yarn build:cloud``` - where "cloud" is environment file mentioned at "Configuration" file
* then copy build file on the server and type 
	```cd /path_to_frontend/psd2-obie-frontend && nohup npx serve -s build & ```
  or create a script file (startOBRI_front.sh) and add following code 
	```cd /path_to_frontend/psd2-obie-frontend && nohup npx serve -s build & ```

#### Docker script example 
```
#!/bin/sh

echo "Enter deployment directory '/path_to_frontend/devops/deployments/obie-rcs-frontend'"
cd /path_to_frontend/devops/deployments/obie-rcs-frontend

echo "Building docker image 'obie-rcs-frontend:1.0 .'"
sudo docker build -t obie-rcs-frontend:1.0 .

echo "Tag docker to match external repository 'gcr.io/partner-portal-223015/obie-rcs-frontend:1.0'"
sudo docker tag obie-rcs-frontend:1.0 gcr.io/partner-portal-223015/obie-rcs-frontend:1.0

echo "Push docker image to Google Container Registry 'gcr.io/partner-portal-223015/obie-rcs-frontend:1.0'"
sudo gcloud docker -- push gcr.io/partner-portal-223015/obie-rcs-frontend:1.0

echo "Deploy obie-rcs-frontend to Google Cloud Kubernetes Engine"
sudo kubectl delete -f obie-rcs-frontend-deployment.yaml
sudo kubectl apply -f obie-rcs-frontend-deployment.yaml
```


## License

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