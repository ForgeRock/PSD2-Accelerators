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
package nl.booleans.oidc.yes.rcs.model;

import java.util.Date;

public class Consent {
    private Date consentDate;
    private String consentedClaim;
    private String consentedClaimDisplay;


    /**
     * Constructor
     */
    public Consent() {
    }


    /**
     * Return the consented date
     *
     * @return - Date object
     */
    public Date getConsentDate() {
        return consentDate;
    }


    /**
     * Set the consented date
     *
     * @param consentDate
     * @return - adjusted Consent object
     */
    public Consent setConsentDate(Date consentDate) {
        this.consentDate = consentDate;
        return this;
    }

    /**
     * Return the consented claim name
     *
     * @return - String containing the consented claim
     */
    public String getConsentedClaim() {
        return consentedClaim;
    }


    /**
     * Set the consented claim
     *
     * @param consentedClaim - name of the claim
     * @return - adjusted Consent object
     */
    public Consent setConsentedClaim(String consentedClaim) {
        this.consentedClaim = consentedClaim;
        return this;
    }


    /**
     * Return the consented claim display name
     *
     * @return - String containing the claim display name
     */
    public String getConsentedClaimDisplay() {
        return consentedClaimDisplay;
    }


    /**
     * Set the consented claim display name
     *
     * @param consentedClaimDisplay
     * @return - Consent object
     */
    public Consent setConsentedClaimDisplay(String consentedClaimDisplay) {
        this.consentedClaimDisplay = consentedClaimDisplay;
        return this;
    }


    /**
     * Returns a string representation of the Consent object
     *
     * @return - String with the object details
     */
    @Override
    public String toString() {
        return "Consent{" +
                "consentDate=" + consentDate +
                ", consentedClaim='" + consentedClaim + '\'' +
                ", consentedClaimDisplay='" + consentedClaimDisplay + '\'' +
                '}';
    }
}
