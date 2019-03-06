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
public class OIDCConstants {
    public static final String JWT_BEARER_CLIENT_ASSERTION_TYPE =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

    public static class Endpoint {
        public static final String WELL_KNOWN = ".well-known/openid-configuration";
    }

    public static class SubjectType {
        public static final String PUBLIC = "public";
        public static final String PAIRWISE = "pairwise";
    }

    public static class TokenEndpointAuthMethods {
        public static final String CLIENT_SECRET_POST = "client_secret_post";
        public static final String CLIENT_SECRET_BASIC = "client_secret_basic";
        public static final String CLIENT_SECRET_JWT = "client_secret_jwt";
        public static final String PRIVATE_KEY_JWT = "private_key_jwt";
    }

    public static class ResponseType {
        public static final String CODE = "code";
        public static final String ID_TOKEN = "id_token";
        public static final String TOKEN = "token";
    }

    public static class GrantType {
        public static final String CLIENT_CREDENTIAL = "client_credentials";
        public static final String AUTHORIZATION_CODE = "authorization_code";
        public static final String REFRESH_TOKEN = "refresh_token";
    }

    public static class OIDCClaim {
        public static final String GRANT_TYPE = "grant_type";
        public static final String ID_TOKEN = "id_token";
        public static final String USER_INFO = "userinfo";
        public static final String CLAIMS = "claims";
        public static final String CONSENT_APPROVAL_REDIRECT_URI = "consentApprovalRedirectUri";
        public static final String RESPONSE_TYPE = "response_type";
        public static final String CLIENT_ID = "client_id";
        public static final String REDIRECT_URI = "redirect_uri";
        public static final String REQUEST = "request";
        public static final String SCOPE = "scope";
        public static final String STATE = "state";
        public static final String NONCE = "nonce";
        public static final String CLIENT_ASSERTION_TYPE = "client_assertion_type";
        public static final String CLIENT_ASSERTION = "client_assertion";
        public static final String CODE = "code";
        public static final String OB_ACR_VALUE = "urn:openbanking:psd2:sca";
        public static final String CONSENT_ID = "consent_id";
        public static final String USERNAME="username";
    }

}

