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
 
function account_access_consent_main(){

	if (request.method == "create") {
		accountConsentResult = createAccountConsent(request.content);
		return accountConsentResult;
	}
	else {
		if (request.method == "patch" || request.method == "action") {
			updateAccountConsentStatusResult = updateAccountConsent(request.content);
			return updateAccountConsentStatusResult;
		}
		else {
			throw { code : 500, message : "Invalid request - only POST implemented for accountConsent" };
		}
	};
}

//Create NextGenPSD2 Account Information Consent with AwaitingAuthorisation status
function createAccountConsent(accountConsentData){

	//Set the Account Information Consent to pending status
	accountConsentData.Status = "received"

	console.log("DATA accountConsentData with status: "+ accountConsentData);

	//Create the IDM NextGenPSD2 Account Information Consent object	
	accountConsentID = openidm.create("/managed/NextGenPSD2AccountAccessConsent", "", accountConsentData);

	accountConsentResponse = {};

        if (accountConsentID != null){
                accountConsentResponse.consentStatus = "received";
                accountConsentResponse.consentId = accountConsentID._id;
                accountConsentResponse._links = {};
                accountConsentResponse._links.scaOAuth = {};
                accountConsentResponse._links.scaOAuth.href = "/oauth2/realms/root/realms/nextgenpsd2/.well-known/openid-configuration";
                accountConsentResponse._links.self = {};
                accountConsentResponse._links.self.href = "/nextgenpsd2/v1.3.2/consents/" + accountConsentID._id;
                accountConsentResponse._links.scaStatus = {};
                accountConsentResponse._links.scaStatus.href = "/nextgenpsd2/v1.3.2/consents/" + accountConsentID._id + "/authorisations/123auth456";
        }
        return accountConsentResponse;
}


//Update NextGenPSD2 Account Information Intent status to Authorised
function updateAccountConsent(accountConsentData){
	
	console.log("[DEBUG] NextGenPSD2 accountConsentData: "+ accountConsentData);
	
	inputAccountConsentId = request.resourcePath;
	console.log("Input Account Information Consent Id: "+ inputAccountConsentId);	
	
	//Update the IDM OB Payment Consent object Status 
	accountConsentID = openidm.patch("/managed/NextGenPSD2AccountAccessConsent/" + inputAccountConsentId, null, accountConsentData.consent);
	
	console.log("RESULT accountConsentID: "+ accountConsentID);
	
	//Provision Authorization Policy in AM
	amServer.ssoToken = AM_login_getSsoToken(amServer);
	policyData = constructAISPPolicyData(inputAccountConsentId, accountConsentData.claims.sub, accountConsentData.claims);
	AM_policy_create(amServer, policyData);
	AM_logout(amServer);
  
    return accountConsentID;
}
