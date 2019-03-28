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
package org.forgerock.openam.oauth2.yes.claims;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.forgerock.openam.oauth2.yes.claims.verified_person_data.Claims;
import org.forgerock.openam.oauth2.yes.claims.verified_person_data.Verification;

@JsonSerialize(include=JsonSerialize.Inclusion.NON_NULL)
public class VerifiedPersonData {
    private Verification verification;
    private Claims claims;

    @JsonProperty("verification")
    public Verification getVerification() {
        return this.verification;
    }

    @JsonProperty("verification")
    public void setVerification(Verification verification) {
        this.verification = verification;
    }

    @JsonProperty("claims")
    public Claims getClaims() {
        return this.claims;
    }

    @JsonProperty("claims")
    public void setClaims(Claims claims) {
        this.claims = claims;
    }

    @Override
    public String toString() {
        return "VerifiedPersonData{" +
                "verification=" + verification +
                ", claims=" + claims +
                '}';
    }
}
