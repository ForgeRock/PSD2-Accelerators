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

function payment_intent_main(){
	
	if (request.method == "create") {
		console.log("DATA obPaymentIntentData request: "+ request);
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
	
	//Set the Payment Intent AwaitingAuthorisation status and creation date time
	paymentIntentData.Data.Status = "AwaitingAuthorisation";
	paymentIntentData.Data.CreationDateTime = generateTimestamp();
	paymentIntentData.Data.StatusUpdateDateTime = generateTimestamp();

	console.log("[DEBUG]: Input REQUEST: " + request);

	if (request.additionalParameters != null){
		var tppId = request.additionalParameters.tppId;
	}

	//Add relation to the Tpp managed object
	var returnObject = {}
    	var tppIdmId = "";
   	if (typeof tppId == 'string') {
        	tppIdmId = findTppByIdentifier(tppId);
       		if (tppIdmId != "-1"){
			paymentIntentData.Tpp = { "_ref" : CONFIG_managedObjects.obTpp + "/" + tppIdmId};
                }
		/*
        	else {
            		returnObject.reason = "Invalid tppIdentifier";
			return returnObject;
        	}
		*/
    	}
    	else{
   		returnObject.reason = "tppIdentifier must be specified as a string";
    	}
		
	console.log("DATA paymentIntentData with status: "+ paymentIntentData);
	
	//Create the IDM OB Payment Intent object
	paymentIntentOutput = openidm.create(CONFIG_managedObjects.obDomesticPayment, "", paymentIntentData);

	var paymentUpdateIntentOutput = "";
	if (paymentIntentOutput != null){
		var updatePaymentIntent = [];
	        //Save ConsentId on the IDM Payment managed object
        	var updateConsentObject = {
                	"operation": "add",
                	"field": "/Data/ConsentId",
                	"value": paymentIntentOutput._id
	        };

		updatePaymentIntent.push(updateConsentObject);
		
	        //Update the IDM OB Payment Intent object Status
        	paymentUpdateIntentOutput = openidm.patch(CONFIG_managedObjects.obDomesticPayment + "/" + paymentIntentOutput._id, null, updatePaymentIntent);
	}
	
	if (paymentUpdateIntentOutput != null){
		paymentIntentOutput = paymentUpdateIntentOutput;
	}
	paymentIntentOutput.Links = {};
	paymentIntentOutput.Links.Self = constructIgUri(igServer) + igServer.domesticPaymentEndpoint + "/" + paymentIntentOutput._id;
	paymentIntentOutput.Meta = {};
	delete paymentIntentOutput._id;
	delete paymentIntentOutput._rev;

	console.log("\nRESULT paymentIntentOutput final: "+ paymentIntentOutput);
  
 	return paymentIntentOutput;
}


//Update OB Payment Intent status to Authorised
function updatePaymentIntent(paymentIntentData){
	
	console.log("[DEBUG] Request: "+ request);
	console.log("[DEBUG] paymentIntentData: "+ paymentIntentData);
	
	inputPaymentIntentId = request.resourcePath;
	console.log("Input Payment Intent Id: "+ inputPaymentIntentId);	

	var userid = paymentIntentData.claims.sub;
	updatePaymentIntent = paymentIntentData.consent;

	for (var i=0; i < updatePaymentIntent.length; i++){
    		if ((updatePaymentIntent[i].field).equals("/Data/Status")){
	      		console.log("[DEBUG] Value of Status element: " + updatePaymentIntent[i].value);
			consentStatusUpdate = updatePaymentIntent[i].value;
			break;
		}
	}

	//Add relation to the USER managed object
        var userIdmId = "";
	var updateUserObject = "";
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
			updatePaymentIntent.push(updateUserObject);

                	var updateStatusDateTimeObject = {
                        	"operation": "replace",
                        	"field": "/Data/StatusUpdateDateTime",
                        	"value": generateTimestamp()
                	};
                	updatePaymentIntent.push(updateStatusDateTimeObject);
                }
        }

	console.log("[DEBUG] updatePaymentIntent: " + updatePaymentIntent);
	
	//Update the IDM OB Payment Intent object Status 
	paymentIntentID = openidm.patch(CONFIG_managedObjects.obDomesticPayment + "/" + inputPaymentIntentId, null, updatePaymentIntent);
	
	console.log("RESULT paymentIntentID: "+ paymentIntentID);
	
	if (consentStatusUpdate != null && consentStatusUpdate.equals("Authorised")){
		//Provision Authorization Policy in AM
		amServer.ssoToken = AM_login_getSsoToken(amServer);
		policyData = constructPISPPolicyData(inputPaymentIntentId, userid, paymentIntentData.claims.Initiation);
		AM_policy_create(amServer, policyData);
		AM_logout(amServer);
	}
	else {
		console.log("[DEBUG] No AM Policy was created due to the Consent Status: " + consentStatusUpdate);
	}
  
	return paymentIntentID;
}

function constructIgUri(igServer){
        var uri = "";

        uri = igServer.protocol + "://" + igServer.host + ":" + igServer.port

        return uri;
}