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
	"host": "10.8.0.5",
	"port": "8080",
	"path": "openam",
	"realm": "root",
	"policyRealm": "nextgenpsd2",
	"username": "amAdmin",
	"password": "password",
	"loggedin": false,
	"ssoToken": ""
}

// IDM server details
var idmServer = {
        "protocol": "https",
        "host": "openidm.psd2accelerators.fridam.aeet-forgerock.com",
        "port": "443"
}

//OBIE IDM Managed Objects
CONFIG_managedObjects = {
	"bgPaymentIntent" : "/managed/BGPaymentIntent",
	"bgAccountAccessConsent" : "/managed/BGAccountAccessConsent",
	"bgTpp" : "/managed/BGTpp"
};
