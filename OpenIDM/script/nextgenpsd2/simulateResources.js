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
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/nextgenpsd2/nextgenpsd2_utils.js");

(function(){
	return "OK";
})();

(function(){
        d = new Date();
        s = d.getTime();
        console.log("[DEBUG] NextGenPSD2 Main API Simulator - " + s);

        returnObject = {};

        switch (thisUriComponent("APPLICATION")) {

                case "nextGenPSD2ConsentDetails":
                        returnObject = consentDetailsSimulator();
                        break;

 		case "nextGenPSD2ConsentStatus":
                        returnObject = consentStatusSimulator();
                        break;

                case "nextGenPSD2AccountList":
                        returnObject = accountListSimulator();
                        break;

                case "nextGenPSD2AccountDetails":
                        returnObject = accountDetailsSimulator();
                        break;

                case "nextGenPSD2PaymentStatus":
                        returnObject = paymentStatusSimulator();
                        break;
        }

    return {
            result: returnObject
    };

})();

function consentDetailsSimulator(){

    console.log("[DEBUG] NextGenPSD2 consent details simulator: "+ request);
    consentDetails = "{\"Consent Details\": \"TBD\"}";

    jsonConsentDetails = JSON.parse(consentDetails);
    return jsonConsentDetails;
}

function consentStatusSimulator(){

    console.log("[DEBUG] NextGenPSD2 consent status simulator: "+ request);
    consentStatus = "{\"Consent Details\": \"TBD\"}";

    jsonConsentStatus = JSON.parse(consentStatus);
    return jsonConsentStatus;
}

function accountListSimulator(){

    console.log("[DEBUG] NextGenPSD2 account list simulator: "+ request);
    accountList = request.additionalParameters;

    jsonAccountList = JSON.parse(accountList);
    return jsonAccountList;
}

function accountDetailsSimulator(){

    console.log("[DEBUG] NextGenPSD2 account details simulator: "+ request);
    accountDetails = "{\"Account Details\":\"Details 123123\"}";

    jsonAccountDetails = JSON.parse(accountDetails);
    return jsonAccountDetails;
}

function paymentStatusSimulator(){

    console.log("[DEBUG] NextGenPSD2 payment status simulator: "+ request);
    paymentStatusResponse = "{\"Payment Status\":\"Confirmed\"}";

    jsonPaymentStatusResponse = JSON.parse(paymentStatusResponse);
    return jsonPaymentStatusResponse;
}

