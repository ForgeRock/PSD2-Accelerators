/*
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
 */
package org.forgerock.openam.oauth2.yes.utils;

import org.forgerock.openidconnect.Claim;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ScopeToClaimsMapper {
    /**
     *
     * @return
     */
    public static Map<String, List<Claim>> getScopeToClaimsMap() {
        // holds all scopes to claims mapping
        Map<String, List<Claim>> scopeToClaimsMap = new HashMap<>();

        /* email scope map */
        scopeToClaimsMap.put("email", Stream.of(
                new Claim("email"),
                new Claim("email_verified")
        ).collect(Collectors.toList()));

        /* phone scope map */
        scopeToClaimsMap.put("phone", Stream.of(
                new Claim("phone_number"),
                new Claim("phone_number_verified")
        ).collect(Collectors.toList()));

        /* address scope map */
        scopeToClaimsMap.put("address", Stream.of(
                new Claim("address")
        ).collect(Collectors.toList()));

        /* profile scope map - may not be used in this context */
        scopeToClaimsMap.put("profile", Stream.of(
                new Claim("name"),
                new Claim("family_name"),
                new Claim("given_name"),
                new Claim("middle_name"),
                new Claim("nickname"),
                new Claim("preferred_username"),
                new Claim("profile"),
                new Claim("picture"),
                new Claim("website"),
                new Claim("gender"),
                new Claim("birthdate"),
                new Claim("zoneinfo"),
                new Claim("locale"),
                new Claim("updated_at")
        ).collect(Collectors.toList()));

        /* person_data scope */
        scopeToClaimsMap.put("https://www.yes.com/scopes/person_data", Stream.of(
                new Claim("given_name"),
                new Claim("family_name"),
                new Claim("gender"),
                new Claim("https://www.yes.com/claims/salutation"),
                new Claim("https://www.yes.com/claims/title"),
                new Claim("https://www.yes.com/claims/place_of_birth"),
                new Claim("birthdate"),
                new Claim("https://www.yes.com/claims/nationality")
        ).collect(Collectors.toList()));

        /* verified_person_data scope */
        scopeToClaimsMap.put("https://www.yes.com/scopes/verified_person_data", Stream.of(
                new Claim("given_name"),
                new Claim("family_name"),
                new Claim("birthdate"),
                new Claim("https://www.yes.com/claims/place_of_birth"),
                new Claim("https://www.yes.com/claims/nationality"),
                new Claim("address"),
                new Claim("https://www.yes.com/claims/transaction_id")
        ).collect(Collectors.toList()));

        /* claim for verified person data is the same as the verified person data scope */
        scopeToClaimsMap.put("https://www.yes.com/claims/verified_person_data", scopeToClaimsMap.get("https://www.yes.com/scopes/verified_person_data"));

        return scopeToClaimsMap;
    }


    /**
     *
     * @param scope
     * @return
     */
    public static List<Claim> getClaimsForScope(String scope) {
        if (scope != null) {
            return getScopeToClaimsMap().get(scope);
        }
        return Collections.emptyList();
    }

    /**
     *
     * @param scopes
     * @param claims
     * @return
     */
    public static Map<String, List<Claim>> getAllRequestedClaims(List<String> scopes, List<String> claims) {
        Map<String, List<Claim>> allRequestedClaimsAndScopesMap = new HashMap<>();

        List<Claim> requestedClaimsForScopes = new ArrayList<>();
        for (String scopeName : scopes) {
            List<Claim> scopeClaims = getClaimsForScope(scopeName);
            if (scopeClaims != null && scopeClaims.size() != 0) {
                requestedClaimsForScopes = mergeClaimList(requestedClaimsForScopes, scopeClaims);
            }
        }

        if (claims != null && claims.size() > 0) {
            for (String claimName : claims) {
                requestedClaimsForScopes.add(new Claim(claimName));
            }
        }

        allRequestedClaimsAndScopesMap.put("claims", requestedClaimsForScopes);
        return allRequestedClaimsAndScopesMap;
    }


    /**
     *
     * @param originalList
     * @param addedList
     * @return
     */
    public static<T> List<T> mergeClaimList(List<T> originalList, List<T> addedList) {
        List<T> mergedList = new ArrayList<>(originalList);
        mergedList.addAll(addedList);

        return mergedList;
    }
}
