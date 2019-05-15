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

(function () {

       var inputAccountIntentId = null;
       if (request.additionalParameters != null){
                inputAccountIntentId = request.additionalParameters.consentId;
        }

	console.log("[DEBUG] onDelete Account Access Consent: " + request);
        console.log("[DEBUG] Delete Consent Id: " + inputAccountIntentId);

        if (inputAccountIntentId != null){
                //Delete Authorization Policy in AM
                amServer.ssoToken = AM_login_getSsoToken(amServer);
                AM_policy_delete(amServer, "aisp-" + inputAccountIntentId);
                AM_logout(amServer);
		console.log("[DEBUG] Policy aisp-" + inputAccountIntentId + " was deleted from AM.");
        }
        else {
                console.log("[DEBUG] No AM Policy was deleted");
        }
}()); 
