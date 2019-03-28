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
import org.forgerock.openam.oauth2.yes.claims.verified_person_data.claims.AddressClaim;
import org.forgerock.openam.oauth2.yes.claims.verified_person_data.claims.PlaceOfBirthClaim;

@JsonSerialize(include=JsonSerialize.Inclusion.NON_NULL)
public class Claims {
    private String givenName;
    private String familyName;
    private String birthDate;
    private PlaceOfBirthClaim placeOfBirthClaim;
    private AddressClaim addressClaim;
    private String nationality;

    @JsonProperty("given_name")
    public String getGivenName() {
        return givenName;
    }

    @JsonProperty("given_name")
    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    @JsonProperty("family_name")
    public String getFamilyName() {
        return familyName;
    }

    @JsonProperty("family_name")
    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    @JsonProperty("birthdate")
    public String getBirthDate() {
        return birthDate;
    }

    @JsonProperty("birthdate")
    public void setBirthDate(String birthDate) {
        this.birthDate = birthDate;
    }

    @JsonProperty("https://www.yes.com/claims/place_of_birth")
    public PlaceOfBirthClaim getPlaceOfBirthClaim() {
        return placeOfBirthClaim;
    }

    @JsonProperty("https://www.yes.com/claims/place_of_birth")
    public void setPlaceOfBirthClaim(PlaceOfBirthClaim placeOfBirthClaim) {
        this.placeOfBirthClaim = placeOfBirthClaim;
    }

    @JsonProperty("address")
    public AddressClaim getAddressClaim() {
        return addressClaim;
    }

    @JsonProperty("address")
    public void setAddressClaim(AddressClaim addressClaim) {
        this.addressClaim = addressClaim;
    }

    @JsonProperty("https://www.yes.com/claims/nationality")
    public String getNationality() {
        return nationality;
    }

    @JsonProperty("https://www.yes.com/claims/nationality")
    public void setNationality(String nationality) {
        this.nationality = nationality;
    }

    @Override
    public String toString() {
        return "Claims{" +
                "givenName='" + givenName + '\'' +
                ", familyName='" + familyName + '\'' +
                ", birthDate='" + birthDate + '\'' +
                ", placeOfBirthClaim=" + placeOfBirthClaim +
                ", addressClaim=" + addressClaim +
                ", nationality='" + nationality + '\'' +
                '}';
    }
}
