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
package org.forgerock.openam.oauth2.yes.claims.verified_person_data;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import org.forgerock.openam.oauth2.yes.claims.verified_person_data.verification.EID;
import org.forgerock.openam.oauth2.yes.claims.verified_person_data.verification.LegalContext;
import org.forgerock.openam.oauth2.yes.claims.verified_person_data.verification.QES;
import org.forgerock.openam.oauth2.yes.claims.verified_person_data.verification.identityVerificationMethod;

@JsonSerialize(include=JsonSerialize.Inclusion.NON_NULL)
public class Verification {
    private String organization;
    private String date;
    private LegalContext legalContext;
    private String id;
    private org.forgerock.openam.oauth2.yes.claims.verified_person_data.verification.identityVerificationMethod identityVerificationMethod;
    private QES qes;
    private EID eid;

    @JsonProperty("organization")
    public String getOrganization() {
        return this.organization;
    }

    @JsonProperty("organization")
    public void setOrganization(String organization) {
        this.organization = organization;
    }

    @JsonProperty("date")
    public String getDate() {
        return this.date;
    }

    @JsonProperty("date")
    public void setDate(String date) {
        this.date = date;
    }

    @JsonProperty("legal_context")
    public LegalContext getLegalContext() {
        return legalContext;
    }

    @JsonProperty("legal_context")
    public void setLegalContext(LegalContext legalContext) {
        this.legalContext = legalContext;
    }

    @JsonProperty("id")
    public String getId() {
        return id;
    }

    @JsonProperty("id")
    public void setId(String id) {
        this.id = id;
    }

    @JsonProperty("method")
    public identityVerificationMethod getIdentityVerificationMethod() {
        return identityVerificationMethod;
    }

    @JsonProperty("method")
    public void setIdentityVerificationMethod(identityVerificationMethod identityVerificationMethod) {
        this.identityVerificationMethod = identityVerificationMethod;
    }

    @JsonProperty("qes")
    public QES getQes() {
        return qes;
    }

    @JsonProperty("qes")
    public void setQes(QES qes) {
        this.qes = qes;
    }

    @JsonProperty("eID")
    public EID getEid() {
        return eid;
    }

    @JsonProperty("eID")
    public void setEid(EID eid) {
        this.eid = eid;
    }

    @Override
    public String toString() {
        return "Verification{" +
                "organization='" + organization + '\'' +
                ", date='" + date + '\'' +
                ", legalContext=" + legalContext +
                ", id='" + id + '\'' +
                ", identityVerificationMethod=" + identityVerificationMethod +
                ", qes=" + qes +
                ", eid=" + eid +
                '}';
    }
}
