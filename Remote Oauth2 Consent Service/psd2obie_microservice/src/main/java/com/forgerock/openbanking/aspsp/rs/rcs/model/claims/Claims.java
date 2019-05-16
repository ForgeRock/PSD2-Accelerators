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
package com.forgerock.openbanking.aspsp.rs.rcs.model.claims;

import net.minidev.json.JSONObject;

import java.util.HashMap;
import java.util.Map;


/**
 * Models OpenID Connect claims that are requested in an authorize request.
 */
public class Claims {

    private final Map<String, Claim> userInfoClaims;
    private final Map<String, Claim> idTokenClaims;

    /**
     * Creates a Claims object.
     *
     * @param userInfoClaims The userinfo claims.
     * @param idTokenClaims  The id_token claims.
     */
    public Claims(Map<String, Claim> userInfoClaims, Map<String, Claim> idTokenClaims) {
        this.userInfoClaims = userInfoClaims;
        this.idTokenClaims = idTokenClaims;
    }

    /**
     * Gets the userinfo claims.
     *
     * @return The userinfo claims.
     */
    public Map<String, Claim> getUserInfoClaims() {
        return userInfoClaims;
    }

    /**
     * Gets the id_token claims.
     *
     * @return The id_token claims.
     */
    public Map<String, Claim> getIdTokenClaims() {
        return idTokenClaims;
    }

    /**
     * Gets all the claims for both userinfo and id_token claims.
     *
     * @return All claims.
     */
    public Map<String, Claim> getAllClaims() {
        Map<String, Claim> claims = new HashMap<>(userInfoClaims);
        claims.putAll(idTokenClaims);
        return claims;
    }

    public static Claims parseClaims(JSONObject claimsJson) {
        return new Claims(parseClaimsFrom("user_info", claimsJson).size()!=0?parseClaimsFrom("user_info", claimsJson):parseClaimsFrom("userinfo", claimsJson), parseClaimsFrom("id_token", claimsJson));
    }

    private static Map<String, Claim> parseClaimsFrom(String key, JSONObject json) {
        Map<String, Claim> claims = new HashMap<>();
        if (json.containsKey(key)) {
            JSONObject claimsAsJson = (JSONObject) json.get(key);
            for (Object claimKey : claimsAsJson.keySet()) {
                claims.put((String) claimKey, Claim.parseClaim((JSONObject) claimsAsJson.get(claimKey)));
            }
        }
        return claims;
    }
}
