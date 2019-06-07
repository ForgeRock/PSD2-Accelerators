/***************************************************************************
 *  Copyright 2019 ForgeRock
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
package com.forgerock.openbanking.aspsp.rs.rcs.constants;

public class OpenBankingConstants {

    public static final String BOOKED_TIME_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss";

    public static class AMAccessTokenClaim {
        public static final String CLAIMS = "claims";
        public static final String ID_TOKEN = "id_token";
        public static final String INTENT_ID = "openbanking_intent_id";
    }

    public static class IdTokenClaim {
        public static final String INTENT_ID = "openbanking_intent_id";
        public static final String ACR = "acr";
        public static final String C_HASH = "c_hash";
        public static final String S_HASH = "s_hash";
        public static final String ID_TOKEN = "id_token";
        public static final String USER_INFO = "user_info";
        public static final String CLAIMS = "claims";
    }

    public static class Scope {
        public static final String PAYMENTS = "payments";
        public static final String OPENID = "openid";
        public static final String ACCOUNTS = "accounts";
    }

    public static class ParametersFieldName {
        public static final String FROM_BOOKING_DATE_TIME = "fromBookingDateTime";
        public static final String TO_BOOKING_DATE_TIME = "toBookingDateTime";
    }

    public static class RegistrationTppRequestClaims {
        public static final String SOFTWARE_ID = "software_id";
        public static final String SOFTWARE_STATEMENT = "software_statement";
        public static final String JWKS_URI = "jwks_uri";
        public static final String REDIRECT_URIS = "redirect_uris";
        public static final String APPLICATION_TYPE_WEB = "web";
    }

    public static class AMRegistrationResponseClaims {
        public static final String CLIENT_ID = "client_id";
    }

    public static class SSAClaims {
        public static final String SOFTWARE_ID = "software_id";
        public static final String SOFTWARE_CLIENT_ID = "software_client_id";
        public static final String SOFTWARE_CLIENT_DESCRIPTION = "software_client_description";
        public static final String SOFTWARE_CLIENT_NAME = "software_client_name";
        public static final String SOFTWARE_VERSION = "software_version";
        public static final String SOFTWARE_ENVIRONMENT = "software_environment";
        public static final String SOFTWARE_JWKS_ENDPOINT = "software_jwks_endpoint";
        public static final String SOFTWARE_JWKS_REVOKED_ENDPOINT = "software_jwks_revoked_endpoint";
        public static final String SOFTWARE_LOGO_URI = "software_logo_uri";
        public static final String SOFTWARE_MODE = "software_mode";
        public static final String SOFTWARE_ON_BEHALF_OF_ORG = "software_on_behalf_of_org";
        public static final String SOFTWARE_ON_BEHALF_OF_ORG_TYPE = "software_on_behalf_of_org_type";
        public static final String SOFTWARE_POLICY_URI = "software_policy_uri";
        public static final String SOFTWARE_REDIRECT_URIS = "software_redirect_uris";
        public static final String SOFTWARE_ROLES = "software_roles";
        public static final String SOFTWARE_TOS_URI = "software_tos_uri";
        public static final String ORGANISATION_COMPETENT_AUTHORITY_CLAIMS = "organisation_competent_authority_claims";
        public static final String ORG_STATUS = "org_status";
        public static final String ORG_ID = "org_id";
        public static final String ORG_NAME = "org_name";
        public static final String ORG_CONTACTS = "org_contacts";
        public static final String ORG_JWKS_ENDPOINT = "org_jwks_endpoint";
        public static final String ORG_JWKS_REVOKED_ENDPOINT = "org_jwks_revoked_endpoint";
        public static final String OB_REGISTRY_TOS = "ob_registry_tos";
    }

    public static class AISPContextClaims {
        public static final String ASPSP_SESSION_CONTEXT = "aspspSessionContext";
        public static final String ASPSP_ID = "aspspId";
    }
    
    public static class OpenIDM{
    	public static final String X_OPENIDM_USERNAME = "X-OpenIDM-Username";
    	public static final String X_OPENIDM_PASSWORD = "X-OpenIDM-Password";
    	public static final String IDM_DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";
    }
    public static class OpenAM{
    	public static final String X_OPENAM_USERNAME = "X-OpenAM-Username";
    	public static final String X_OPENAM_PASSWORD = "X-OpenAM-Password";
    }
    
    public static class AISP{
    	public static final String AISP_FLOW = "aisp";
    	public static final String AISP_FLOW_AUTO_ACCEPT = "aisp_auto_accept";
    }
    public static class PISP{
    	public static final String PISP_FLOW = "pisp";
    }
    public static class InternRCS{
    	public static final String SCOPES_LIST = "scopeList";
    	public static final String CLIENT_NAME = "client_name";
    	public static final String USERNAME = "username";
    	public static final String CLIENT_ID = "clientId";
    }
}