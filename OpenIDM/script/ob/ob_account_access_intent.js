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
 
function account_access_intent_main(){

	if (request.method == "create") {
		accountIntentResult = createAccountIntent(request.content);
		return accountIntentResult;
	}
	else {
		if (request.method == "patch" || request.method == "action") {
			updateAccountIntentStatusResult = updateAccountIntent(request.content);
			return updateAccountIntentStatusResult;
		}
		else {
			throw { code : 500, message : "Invalid request - only POST implemented for accountIntent" };
		}
	};
}

function createAccountIntent(accountIntentData){

	//Set the Account Information Intent pending status
	accountIntentData.Status = "AwaitingAuthorisation"

	console.log("DATA accountIntentData with status: "+ accountIntentData);

	//Create the IDM OB Account Information Intent object	
	accountIntentID = openidm.create("/managed/OBAccountAccessIntent", "", accountIntentData);
	
	console.log("RESULT accountIntentID: "+ accountIntentID);
    
    return accountIntentID._id;
}


//Update OB Account Information Intent status to Authorised
function updateAccountIntent(accountIntentData){
	
	console.log("[DEBUG] Request: "+ request);
	console.log("[DEBUG] accountIntentData: "+ accountIntentData);
	
	inputAccountIntentId = request.resourcePath;
	console.log("Input Account Information Intent Id: "+ inputAccountIntentId);	
	
	//Update the IDM OB Payment Intent object Status 
	accountIntentID = openidm.patch("/managed/OBAccountAccessIntent/" + inputAccountIntentId, null, accountIntentData.consent);
	
	console.log("RESULT accountIntentID: "+ accountIntentID);
	
	//Provision Authorization Policy in AM
	amServer.ssoToken = AM_login_getSsoToken(amServer);
	policyData = constructAISPPolicyData(inputAccountIntentId, accountIntentData.claims.sub, accountIntentData.claims.accounts);
	AM_policy_create(amServer, policyData);
	AM_logout(amServer);
  
    return accountIntentID;
}
