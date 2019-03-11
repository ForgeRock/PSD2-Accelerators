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
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/bg/bg_utils.js");

(function(){
	return "OK";
})();

(function(){
        d = new Date();
        s = d.getTime();
        console.log("Main API Simulator - " + s);

        returnObject = {};

        switch (thisUriComponent("APPLICATION")) {

                case "bgConsentDetails":
                        returnObject = consentDetailsSimulator();
                        break;

 		case "bgConsentStatus":
                        returnObject = consentStatusSimulator();
                        break;

                case "bgAccountList":
                        returnObject = accountListSimulator();
                        break;

                case "bgAccountDetails":
                        returnObject = accountDetailsSimulator();
                        break;

                case "bgPaymentStatus":
                        returnObject = paymentStatusSimulator();
                        break;
        }

    return {
            result: returnObject
    };

})();

function consentDetailsSimulator(){

    console.log("[DEBUG] consent details simulator: "+ request);
    consentDetails = "{\"Consent Details\": \"TBD\"}";

    jsonConsentDetails = JSON.parse(consentDetails);
    return jsonConsentDetails;
}

function consentStatusSimulator(){

    console.log("[DEBUG] consent status simulator: "+ request);
    consentStatus = "{\"Consent Details\": \"TBD\"}";

    jsonConsentStatus = JSON.parse(consentStatus);
    return jsonConsentStatus;
}

function accountListSimulator(){

    console.log("[DEBUG] account list simulator: "+ request);
    accountList = request.additionalParameters;

    jsonAccountList = JSON.parse(accountList);
    return jsonAccountList;
}

function accountDetailsSimulator(){

    console.log("[DEBUG] account details simulator: "+ request);
    accountDetails = "{\"Account Details\":\"Details 123123\"}";

    jsonAccountDetails = JSON.parse(accountDetails);
    return jsonAccountDetails;
}

function paymentStatusSimulator(){

    console.log("[DEBUG] payment status simulator: "+ request);
    paymentStatusResponse = "{\"Payment Status\":\"Confirmed\"}";

    jsonPaymentStatusResponse = JSON.parse(paymentStatusResponse);
    return jsonPaymentStatusResponse;
}

