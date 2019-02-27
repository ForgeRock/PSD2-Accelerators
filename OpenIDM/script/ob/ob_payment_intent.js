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
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/ob/config.js");
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/ob/fr_am_utils.js");
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/ob/ob_am_policy.js");

function payment_intent_main(){
	
	if (request.method == "create") {
		console.log("DATA paymentIntentData request: "+ request);
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

//Create initial OB Payment Intent object with status Pending
function createPaymentIntent(paymentIntentData){
	
	//Set the Payment Intent pending status
	paymentIntentData.Status = "Pending"
	
	console.log("DATA paymentIntentData with status: "+ paymentIntentData);
	
	//Create the IDM OB Payment Intent object
    paymentIntentID = openidm.create("/managed/OBPaymentIntent", "", paymentIntentData);
	
	console.log("\nRESULT paymentIntentID: "+ paymentIntentID);
  
    return paymentIntentID._id;
}


//Update OB Payment Intent status to Authorised
function updatePaymentIntent(paymentIntentData){
	
	console.log("[DEBUG] Request: "+ request);
	console.log("[DEBUG] paymentIntentData: "+ paymentIntentData);
	
	inputPaymentIntentId = request.resourcePath;
	console.log("Input Payment Intent Id: "+ inputPaymentIntentId);	
	
	//Update the IDM OB Payment Intent object Status 
    paymentIntentID = openidm.patch("/managed/OBPaymentIntent/" + inputPaymentIntentId, null, paymentIntentData.consent);
	
	console.log("RESULT paymentIntentID: "+ paymentIntentID);
	
	//Provision Authorization Policy in AM
	amServer.ssoToken = AM_login_getSsoToken(amServer);
	policyData = constructPISPPolicyData(inputPaymentIntentId, paymentIntentData.claims.sub, paymentIntentData.claims.Initiation);
	AM_policy_create(amServer, policyData);
	AM_logout(amServer);
  
    return paymentIntentID;
}