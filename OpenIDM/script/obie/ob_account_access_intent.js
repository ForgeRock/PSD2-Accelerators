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
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/obie/config.js");
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/obie/ob_utils.js");
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/obie/fr_am_utils.js");
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/obie/ob_am_policy.js");
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/obie/ob_tpp.js");
 
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

        //Set the Payment Intent AwaitingAuthorisation status and creation date time
        accountIntentData.Data.Status = "AwaitingAuthorisation";
        accountIntentData.Data.CreationDateTime = generateTimestamp();
        accountIntentData.Data.StatusUpdateDateTime = generateTimestamp();

       if (request.additionalParameters != null){
                var tppId = request.additionalParameters.tppId;
        }

        //Add relation to the Tpp managed object
        var returnObject = {}
        var newObject = {}
        var tppIdmId = "";
        if (typeof tppId == 'string') {
                tppIdmId = findTppByIdentifier(tppId);
                if (tppIdmId != "-1"){
                        accountIntentData.Tpp = { "_ref" : CONFIG_managedObjects.obTpp + "/" + tppIdmId};
                }
                else {
                        returnObject.reason = "Invalid tppIdentifier";
                        return returnObject;
                }
        }
        else{
                returnObject.reason = "tppIdentifier must be specified as a string";
        }

        console.log("DATA accountIntentData with status: "+ accountIntentData);

        //Create the IDM OB Payment Intent object
        accountAccessOutput = openidm.create(CONFIG_managedObjects.obAccountAccess, "", accountIntentData);

	var accountUpdateIntentOutput = "";
        if (accountAccessOutput != null){
                var updateAccountIntent = [];
                //Save ConsentId on the IDM Account Access managed object
                var updateConsentObject = {
                        "operation": "add",
                        "field": "/Data/ConsentId",
                        "value": accountAccessOutput._id
                };

                updateAccountIntent.push(updateConsentObject);

                //Update the IDM OB Payment Intent object Status
                accountUpdateIntentOutput = openidm.patch(CONFIG_managedObjects.obAccountAccess + "/" + accountAccessOutput._id, null, updateAccountIntent);
        }

        if (accountUpdateIntentOutput != null){
                accountAccessOutput = accountUpdateIntentOutput;
        }

        accountAccessOutput.Links = {};
        accountAccessOutput.Links.Self = constructIgUri(igServer) + igServer.accountAccessEndpoint + "/" + accountAccessOutput._id;
        accountAccessOutput.Meta = {};
        delete accountAccessOutput._id;
        delete accountAccessOutput._rev;

        console.log("\nRESULT accountAccessOutput final: "+ accountAccessOutput);
   
	return accountAccessOutput;
}


//Update OB Account Information Intent status to Authorised
function updateAccountIntent(accountIntentData){
	
	console.log("[DEBUG] Request: "+ request);
	console.log("[DEBUG] accountIntentData: "+ accountIntentData);
	
	inputAccountIntentId = request.resourcePath;
	console.log("Input Account Information Intent Id: "+ inputAccountIntentId);	

        var userid = accountIntentData.claims.sub;
        updateAccountAccessIntent = accountIntentData.consent;

        for (var i=0; i < updateAccountAccessIntent.length; i++){
                if ((updateAccountAccessIntent[i].field).equals("/Data/Status")){
                        console.log("[DEBUG] Value of Status element: " + updateAccountAccessIntent[i].value);
                        consentStatusUpdate = updateAccountAccessIntent[i].value;
                        break;
                }
        }

        //Add relation to the USER managed object
        var userIdmId = "";
        if (typeof userid == 'string') {
                userIdmId = findUser(userid);
                console.log("[DEBUG] User: " + userid + " has the IDM ID: " + userIdmId);
                if (userIdmId != "-1"){
                        updateUserObject = {
                                "operation":"add",
                                "field":"User",
                                "value":{
                                        "_ref": "managed/user/" + userIdmId,
                                }
                        };
                        updateAccountAccessIntent.push(updateUserObject);

                        var updateStatusDateTimeObject = {
                                "operation": "replace",
                                "field": "/Data/StatusUpdateDateTime",
                                "value": generateTimestamp()
                        };
                        updateAccountAccessIntent.push(updateStatusDateTimeObject);
                }
        }
        console.log("[DEBUG] updateAccountAccessIntent: " + updateAccountAccessIntent);

	
	//Update the IDM OB Account Access Intent object Status 
	accountIntentID = openidm.patch(CONFIG_managedObjects.obAccountAccess + "/" + inputAccountIntentId, null, updateAccountAccessIntent);
	
	console.log("RESULT accountIntentID: "+ accountIntentID);
	

        if (consentStatusUpdate != null && consentStatusUpdate.equals("Authorised")){
		//Provision Authorization Policy in AM
		amServer.ssoToken = AM_login_getSsoToken(amServer);
		policyData = constructAISPPolicyData(inputAccountIntentId, userid, accountIntentData.claims.accounts);
		AM_policy_create(amServer, policyData);
		AM_logout(amServer);
	}
	else {
                console.log("[DEBUG] No AM Policy was created due to the Consent Status: " + consentStatusUpdate);
        }
  
    return accountIntentID;
}

function constructIgUri(igServer){
        var uri = "";

        uri = igServer.protocol + "://" + igServer.host + ":" + igServer.port

        return uri;
}
