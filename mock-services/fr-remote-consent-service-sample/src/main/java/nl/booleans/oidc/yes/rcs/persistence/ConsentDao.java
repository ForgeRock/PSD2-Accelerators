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
package nl.booleans.oidc.yes.rcs.persistence;

import nl.booleans.oidc.yes.rcs.model.Consent;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * This serves as a starting point for implementing your own data persistence.
 *
 * This implementation keeps it in memory and does not persist the data anywhere, data is available
 * as long as the JVM is up.
 *
 */
public enum ConsentDao {
    instance;

    /* in-memory persistence as an example */
    private final ConcurrentHashMap<String, Map<String, Consent>> consentMap;


    /**
     * Constructor
     */
    ConsentDao() {
        consentMap = new ConcurrentHashMap<>();
    }


    /**
     * Store granted consent in memory.
     *
     * @param username - the username for which to store the consent
     * @param consent - a consent object containing consent details
     */
    public void saveConsent(String username, Consent consent) {
        if (this.getConsentMap().get(username) != null) {
            this.getConsentMap().get(username).put(consent.getConsentedClaim(), consent);
        } else {
            Map<String, Consent> newConsent = new HashMap<>();
            newConsent.put(consent.getConsentedClaim(), consent);
            this.getConsentMap().put(username, newConsent);
        }
    }


    /**
     * Returns a map of all the previous consent for a particular user
     *
     * @param username - the username for which to return all consent
     * @return - a map containing the name of the consent and the associated 'Consent' object
     */
    public Map<String, Consent> getAllConsent(String username) {
        return this.getConsentMap().get(username);
    }


    /**
     * Returns the consent for a particular name. Returns null if not available.
     *
     * @param username - the username for which to return the consent
     * @param claimName - the name of the consent property
     * @return - a Consent object
     */
    public Consent getConsent(String username, String claimName) {
        return this.getConsentMap().get(username).get(claimName);
    }


    /**
     * Returns a boolean value to indicate whether a specific consent has been previously stored.
     *
     * @param username - the username to look for a specific consent
     * @param claimName - the name of the consent property
     * @return - boolean to indicate whether consent has been given previously
     */
    public Boolean hasConsented(String username, String claimName) {
        if (this.getConsentMap().get(username) != null) {
            if (this.getConsent(username, claimName) != null) {
                return true;
            }
        }
        return false;
    }


    /**
     * Returns the map of all granted consent
     *
     * @return - map containg a username to consent mapping.
     */
    private Map<String, Map<String, Consent>> getConsentMap() {
        return this.consentMap;
    }
}
