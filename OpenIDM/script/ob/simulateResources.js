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
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/ob/ob_utils.js");

(function(){
	return "OK";
})();

(function(){
        d = new Date();
        s = d.getTime();
        console.log("Main API Simulator - " + s);

        returnObject = {};

        switch (thisUriComponent("APPLICATION")) {

                case "accountDetails":
                        returnObject = accountDetailsSimulator();
                        break;

 		case "accountList":
                        returnObject = accountListSimulator();
                        break;
		
		case "accountBalances":
                        returnObject = accountBalancesSimulator();
                        break;

                case "submitPayment":
                        returnObject = submitPaymentSimulator();
                        break;

                case "paymentStatus":
                        returnObject = paymentStatusSimulator();
                        break;
        }

    return {
            result: returnObject
    };

})();

function accountDetailsSimulator(){

    console.log("[DEBUG] account details simulator: "+ request);
    accountDetails = "{\"Data\":{\"Account\":[{\"AccountId\":\"22289\",\"Currency\":\"GBP\",\"AccountType\":\"Personal\",\"AccountSubType\":\"CurrentAccount\",\"Nickname\":\"Bills\",\"Account\":{\"SchemeName\":\"UK.OBIE.SortCodeAccountNumber\",\"Identification\":\"80200110203345\",\"Name\":\"Mr Kevin\",\"SecondaryIdentification\":\"00021\"}}]},\"Links\":{\"Self\":\"https://api.alphabank.com/open-banking/v3.1/aisp/accounts/22289\"},\"Meta\":{\"TotalPages\":1}}";

    jsonAccountDetails = JSON.parse(accountDetails);
    return jsonAccountDetails;
}

function accountListSimulator(){

    console.log("[DEBUG] account list simulator: "+ request);
    accountList = request.additionalParameters;

    jsonAccountList = JSON.parse(accountList);
    return jsonAccountList;
}

function accountBalancesSimulator(){

    console.log("[DEBUG] account balances simulator: "+ request);
    accountBalances = "{\"Data\":{\"Balance\":[{\"AccountId\":\"22289\",\"Amount\":{\"Amount\":\"1230.00\",\"Currency\":\"GBP\"},\"CreditDebitIndicator\":\"Credit\",\"Type\":\"InterimAvailable\",\"DateTime\":\"2017-04-05T10:43:07+00:00\",\"CreditLine\":[{\"Included\":true,\"Amount\":{\"Amount\":\"1000.00\",\"Currency\":\"GBP\"},\"Type\":\"Pre-Agreed\"}]}]},\"Links\":{\"Self\":\"https://api.alphabank.com/open-banking/v3.1/aisp/accounts/22289/balances/\"},\"Meta\":{\"TotalPages\":1}}";

    jsonAccountBalances = JSON.parse(accountBalances);
    return jsonAccountBalances;
}

function submitPaymentSimulator(){

    console.log("[DEBUG] submit payment simulator: "+ request);
    submitPaymentResponse = "TBD";

    jsonSubmitPaymentResponse = JSON.parse(submitPaymentResponse);
    return jsonSubmitPaymentResponse;
}

function paymentStatusSimulator(){

    console.log("[DEBUG] payment status simulator: "+ request);
    paymentStatusResponse = "Confirmed";

    jsonPaymentStatusResponse = JSON.parse(paymentStatusResponse);
    return jsonPaymentStatusResponse;
}

