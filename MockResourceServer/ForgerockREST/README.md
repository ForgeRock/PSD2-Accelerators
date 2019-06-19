# Resource Server Mock Example

A 'Resource Server Mock Service' (aka 'RS') is a  mock service that can be interrogated as part of the [Open Data API specification](https://openbanking.atlassian.net/wiki/spaces/DZ/pages/937656404/Read+Write+Data+API+Specification+-+v3.1) flow where can get payment details, accounts, transactions, balances.
This project serves as a starting point for anyone attempting to implement their own Resource Server.

This resource server contains the following endpoints:

* ```GET /obRSDiscovery/``` - endpoint for display all opentIG endpoints for Open Banking
* ```POST /domestic-payments/``` - endpoint for create a domestic payment
* ```GET /domestic-payments/{id}``` - endpoint for returning a domestic payment which can be consumed only after creation "domestic-payment" endpoint
* ```GET /domestic-payment-consents/{DomesticPaymentId}/funds-confirmation``` - endpoint for returning if funds are available 
* ```GET /accounts/``` - endpoint for returning all account
* ```GET /accounts/{id}``` - endpoint for returning account by ID
* ```GET /accounts/?accounts={accounts}``` - endpoint for returning account by JWT
	e.g. - /accounts/?accounts=eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhY2NvdW50cyI6WyIyMjI4OSIsIjMxODIwIl19.
* ```GET /balances/``` - endpoint for returning all account with balances
* ```GET /accounts/{id}/balances``` - endpoint for returning account by id with balances
* ```GET /transactions/``` - endpoint for returning all transactions
* ```GET /accounts/{id}/transactions``` - endpoint for returning transactions by account id

For configuration you can find file in project:

* **/ForgerockREST/src/main/resources/application.properties**
* **server.port=8089** - application will start on port 8089
* **spring.jackson.default-property-inclusion=non_null** - ignore null value in JSON on create response object.

## Running RS Mock Service

### Run on a local environment 
* Create jar:  ```mvn clean install```
* Run application: ```mvn spring-boot:run```
	
### Run on a different environment 
* Run application : ```java -jar ForgerockREST-0.0.1-SNAPSHOT.jar```
* Or create a script file (startMockOBRI.sh) and add line:
```cd /path_to_location/OBIE_Mock && nohup java -jar ForgerockREST-0.0.1-SNAPSHOT.jar &```


### Run on a kubernetes environment
* Create file "deploy-obie-rcs-mocks.sh" with the following script:
```
#!/bin/sh

echo "Enter deployment directory '/home/iss/devops/deployments/obie-rcs-mocks'"
cd /path_to_another_location/obie-rcs-mocks

echo "Building docker image 'obie-rcs-mocks:1.0 .'"
sudo docker build -t obie-rcs-mocks:1.0 .

echo "Tag docker to match external repository 'gcr.io/partner-portal-223015/obie-rcs-mocks:1.0'"
sudo docker tag obie-rcs-mocks:1.0 gcr.io/partner-portal-223015/obie-rcs-mocks:1.0

echo "Push docker image to Google Container Registry 'gcr.io/partner-portal-223015/obie-rcs-mocks:1.0'"
sudo gcloud docker -- push gcr.io/partner-portal-223015/obie-rcs-mocks:1.0

echo "Deploy obie-rcs-mocks to Google Cloud Kubernetes Engine"
sudo kubectl delete -f obie-rcs-mocks-deployment.yaml
sudo kubectl apply -f obie-rcs-mocks-deployment.yaml
```

### Some examples of API calls: 

* Create domestic-payment:
```
curl -X POST \
  http://host:port/domestic-payments/ \
  -H 'Content-Type: application/json' \
  -H 'cache-control: no-cache' \
  -d ' {
    "Data": {
 "DomesticPaymentId": "pymt-07408c30-203b",
        "ConsentId": "07408c30-203b-4400-99e5-ed5a15f23774",
        "Status": "AwaitingAuthorisation",
        "CreationDateTime": "2019-04-16T06:25:09.662Z",
        "StatusUpdateDateTime": "2019-04-16T06:25:09.662Z",
 "ExpectedExecutionDateTime": "2019-04-30T06:25:09.662Z",
 "ExpectedSettlementDateTime": "2019-04-30T06:25:09.662Z",
 "Charges": {
            "ChargeBearer": "Bearer123",
            "Type": "BearerType",
            "Amount": {
                "Amount": "165.88",
                "Currency": "GBP"
            }
        },
 "Initiation": {
            "InstructionIdentification": "ACME412",
            "EndToEndIdentification": "FRESCO.21302.GFX.20",
            "InstructedAmount": {
                "Amount": "165.88",
                "Currency": "GBP"
            },
            "CreditorAccount": {
                "SchemeName": "UK.OBIE.SortCodeAccountNumber",
                "Identification": "08080021325698",
                "Name": "ACME Inc",
                "SecondaryIdentification": "0002"
            },
            "RemittanceInformation": {
                "Reference": "FRESCO-101",
                "Unstructured": "Internal ops code 5120101"
            }
        }
    }
}'
```

* Create Account Access Consents
```
curl -X POST \
  http://host:port/account-access-consents/ \
  -H 'Content-Type: application/json' \
  -H 'cache-control: no-cache' \
  -d '{
  "Data": {
    "Permissions": [
      "ReadAccountsDetail",
      "ReadBalances",
      "ReadBeneficiariesDetail",
      "ReadDirectDebits",
      "ReadProducts",
      "ReadStandingOrdersDetail",
      "ReadTransactionsCredits",
      "ReadTransactionsDebits",
      "ReadTransactionsDetail",
      "ReadOffers",
      "ReadPAN",
      "ReadParty",
      "ReadPartyPSU",
      "ReadScheduledPaymentsDetail",
      "ReadStatementsDetail"
    ],
    "ExpirationDateTime": "2017-05-02T00:00:00+00:00",
    "TransactionFromDateTime": "2017-05-03T00:00:00+00:00",
    "TransactionToDateTime": "2017-12-03T00:00:00+00:00"
  },
  "Risk": {}
}'
```

* Create domestic payment consents
```
curl -X POST \
  http://18.211.177.234:8089/domestic-payment-consents \
  -H 'Accept: */*' \
  -H 'Cache-Control: no-cache' \
  -H 'Connection: keep-alive' \
  -H 'Content-Type: application/json' \
  -H 'cache-control: no-cache' \
  -H 'content-length: 764' \
  -d '{
  "Data": {
    "Initiation": {
      "InstructionIdentification": "ANSM023",
      "EndToEndIdentification": "FRESCO.21302.GFX.37",
      "InstructedAmount": {
        "Amount": "20.00",
        "Currency": "GBP"
      },
      "DebtorAccount": {
        "SchemeName": "SortCodeAccountNumber",
        "Identification": "11280001234567",
        "Name": "Andrea Smith"
      },
      "CreditorAccount": {
        "SchemeName": "SortCodeAccountNumber",
        "Identification": "08080021325698",
        "Name": "Bob Clements"
      },
      "RemittanceInformation": {
        "Reference": "FRESCO-037",
        "Unstructured": "Internal ops code 5120103"
      }
    }
  },
  "Risk": {
    "PaymentContextCode": "PartyToParty"
  }
}'
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