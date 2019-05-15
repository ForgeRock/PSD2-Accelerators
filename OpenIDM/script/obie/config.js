/***************************************************************************
 *  Copyright 2019 ForgeRock AS.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ***************************************************************************/

// AM server details
var amServer = {
	"protocol": "http",
	"host": "10.8.11.4",
	"port": "8080",
	"path": "openam",
	"realm": "root",
	"policyRealm": "openbanking",
	"username": "amAdmin",
	"password": "password",
	"loggedin": false,
	"ssoToken": ""
};

// IDM server details
var idmServer = {
        "protocol": "https",
        "host": "openidm.psd2acceldemo.fridam.aeet-forgerock.com",
        "port": "443"
};

//IG server details
var igServer = {
	"protocol": "https",
	"host": "openig.psd2acceldemo.fridam.aeet-forgerock.com",
	"port": "443",
	"domesticPaymentEndpoint": "/openbanking/v3.1/domestic-payment-consents",
	"accountAccessEndpoint": "/openbanking/v3.1/account-access-consents"
};

// Resource Server details
var rsServer = {
        "protocol": "http",
        "host": "obie-rcs-mocks.psd2acceldemo.svc.cluster.local",
        "port": "8089"
};


//OBIE IDM Managed Objects
var CONFIG_managedObjects = {
	"obDomesticPayment" : "/managed/ObDomesticPayment",
	"obAccountAccess" : "/managed/ObAccountAccess",
	"obTpp" : "/managed/obTpp",
	"obTppSsa" : "/managed/obTppSsa",
	"user": "/managed/user"
};

//OBIE AM Policy Configs
var CONFIG_policy = {
	"pispResourceTypeUuid" : "76656a38-5f8e-401b-83aa-4ccb74ce88d2",
	"aispResourceTypeUuid" : "76656a38-5f8e-401b-83aa-4ccb74ce88d2"
};
