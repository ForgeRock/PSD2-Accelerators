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
 
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/bg/bg_payment_intent.js");
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/bg/bg_account_access_consent.js");
load("/git/config/6.5/default/idm/sync-with-ldap-bidirectional/script/bg/bg_utils.js");

(function(){
	d = new Date();
	s = d.getTime();
	console.log("Main BG Handler - " + s);
    
	returnObject = {};
	
	switch (thisUriComponent("APPLICATION")) {
    
		case "bgPaymentIntent":
			returnObject = payment_intent_main();
			break;
			
		case "bgAccountAccessConsent":
			returnObject = account_access_consent_main();
			break;
	}
			
    return {
            result: returnObject
    };

})();
