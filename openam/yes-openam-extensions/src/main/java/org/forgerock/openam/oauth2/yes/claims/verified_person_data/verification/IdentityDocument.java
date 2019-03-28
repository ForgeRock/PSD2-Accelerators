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
package org.forgerock.openam.oauth2.yes.claims.verified_person_data.verification;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;

@JsonSerialize(include=JsonSerialize.Inclusion.NON_NULL)
public class IdentityDocument {
    private String country;
    private String type; // should be enum
    private String issuer;
    private String documentNumber;
    private String dateOfIssuance;
    private String dateOfExpiry;
    private String identityDocumentVerificationMethod; // should be enum
    private String organization;
    private String verifyingAgent;

    @JsonProperty("country")
    public String getCountry() {
        return country;
    }

    @JsonProperty("country")
    public void setCountry(String country) {
        this.country = country;
    }

    @JsonProperty("type")
    public String getType() {
        return type;
    }

    @JsonProperty("type")
    public void setType(String type) {
        this.type = type;
    }

    @JsonProperty("issuer")
    public String getIssuer() {
        return issuer;
    }

    @JsonProperty("issuer")
    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    @JsonProperty("number")
    public String getDocumentNumber() {
        return documentNumber;
    }

    @JsonProperty("number")
    public void setDocumentNumber(String documentNumber) {
        this.documentNumber = documentNumber;
    }

    @JsonProperty("date_of_issuance")
    public String getDateOfIssuance() {
        return dateOfIssuance;
    }

    @JsonProperty("date_of_issuance")
    public void setDateOfIssuance(String dateOfIssuance) {
        this.dateOfIssuance = dateOfIssuance;
    }

    @JsonProperty("date_of_expiry")
    public String getDateOfExpiry() {
        return dateOfExpiry;
    }

    @JsonProperty("date_of_expiry")
    public void setDateOfExpiry(String dateOfExpiry) {
        this.dateOfExpiry = dateOfExpiry;
    }

    @JsonProperty("method")
    public String getIdentityDocumentVerificationMethod() {
        return identityDocumentVerificationMethod;
    }

    @JsonProperty("method")
    public void setIdentityDocumentVerificationMethod(String identityDocumentVerificationMethod) {
        this.identityDocumentVerificationMethod = identityDocumentVerificationMethod;
    }

    @JsonProperty("organization")
    public String getOrganization() {
        return organization;
    }

    @JsonProperty("organization")
    public void setOrganization(String organization) {
        this.organization = organization;
    }

    @JsonProperty("agent")
    public String getVerifyingAgent() {
        return verifyingAgent;
    }

    @JsonProperty("agent")
    public void setVerifyingAgent(String verifyingAgent) {
        this.verifyingAgent = verifyingAgent;
    }

    @Override
    public String toString() {
        return "IdentityDocument{" +
                "country='" + country + '\'' +
                ", type='" + type + '\'' +
                ", issuer='" + issuer + '\'' +
                ", documentNumber='" + documentNumber + '\'' +
                ", dateOfIssuance='" + dateOfIssuance + '\'' +
                ", dateOfExpiry='" + dateOfExpiry + '\'' +
                ", identityDocumentVerificationMethod='" + identityDocumentVerificationMethod + '\'' +
                ", organization='" + organization + '\'' +
                ", verifyingAgent='" + verifyingAgent + '\'' +
                '}';
    }
}
