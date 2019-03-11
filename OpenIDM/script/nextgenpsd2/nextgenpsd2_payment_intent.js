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
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/nextgenpsd2/config.js");
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/nextgenpsd2/fr_am_utils.js");
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/nextgenpsd2/nextgenpsd2_am_policy.js");

function payment_intent_main(){
	
	if (request.method == "create") {
		console.log("DATA NextGenPSD2 paymentIntentData request: "+ request);
		paymentIntentResult = createPaymentIntent(request.content);
		return paymentIntentResult;
	}
	else {
		if (request.method == "patch" || request.method == "action") {
			updatePaymentIntentStatusResult = updatePaymentIntent(request.content);
			return updatePaymentIntentStatusResult;
		}
		else {
			throw { code : 500, message : "Invalid request - only POST implemented for paymentIntent" };
		}
	};
}

//Create initial NextGenPSD2 Payment Intent object with status Pending
function createPaymentIntent(paymentIntentData){
	
	//Set the Payment Intent pending status
	paymentIntentData.Status = "RCVD"
	paymentIntentResponse = {};

	console.log("DATA paymentIntentData with status: "+ paymentIntentData);
	
	//Create the IDM NextGenPSD2 Payment Intent object
    	paymentIntentID = openidm.create("/managed/NextGenPSD2PaymentIntent", "", paymentIntentData);
	
	console.log("\nRESULT paymentIntentID: "+ paymentIntentID);
  
	if (paymentIntentID != null){
		paymentIntentResponse.transactionStatus = "RCVD";
		paymentIntentResponse.paymentId = paymentIntentID._id;
		paymentIntentResponse._links = {};
		paymentIntentResponse._links.scaOAuth = {};
		paymentIntentResponse._links.scaOAuth.href = "/oauth2/realms/root/realms/nextgenpsd2/.well-known/openid-configuration";
		paymentIntentResponse._links.self = {};
		paymentIntentResponse._links.self.href = "/nextgenpsd2/v1.3.2/payments/sepa-credit-transfers/" + paymentIntentID._id;
		paymentIntentResponse._links.status = {};
		paymentIntentResponse._links.status.href = "/nextgenpsd2/v1.3.2/payments/sepa-credit-transfers/" + paymentIntentID._id + "/status";
		paymentIntentResponse._links.scaStatus = {};
		paymentIntentResponse._links.scaStatus.href = "/nextgenpsd2/v1.3.2/payments/sepa-credit-transfers/" + paymentIntentID._id + "/authorisations/123auth456";
	}
	return paymentIntentResponse;
}


//Update NextGenPSD2 Payment Intent status to Authorised
function updatePaymentIntent(paymentIntentData){
	
	console.log("[DEBUG] NextGenPSD2 update paymentIntentData: "+ paymentIntentData);
	
	inputPaymentIntentId = request.resourcePath;
	
	//Update the IDM NextGenPSD2 Payment Intent object Status 
    	paymentIntentID = openidm.patch("/managed/NextGenPSD2PaymentIntent/" + inputPaymentIntentId, null, paymentIntentData.consent);

	console.log("RESULT paymentIntentID: "+ paymentIntentID);
	
	//Provision Authorization Policy in AM
	amServer.ssoToken = AM_login_getSsoToken(amServer);
	policyData = constructPISPPolicyData(inputPaymentIntentId, paymentIntentData.claims.sub, paymentIntentData.claims.Initiation);
	AM_policy_create(amServer, policyData);
	AM_logout(amServer);
  
    return paymentIntentID;
}