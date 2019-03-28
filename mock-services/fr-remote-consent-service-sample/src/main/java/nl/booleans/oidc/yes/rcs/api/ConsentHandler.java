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
package nl.booleans.oidc.yes.rcs.api;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEDecrypter;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyType;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import net.minidev.json.JSONObject;
import nl.booleans.oidc.yes.rcs.api.exceptions.DecryptionException;
import nl.booleans.oidc.yes.rcs.api.exceptions.InvalidJwt;
import nl.booleans.oidc.yes.rcs.model.Consent;
import nl.booleans.oidc.yes.rcs.persistence.ConsentDao;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.ws.rs.core.MultivaluedMap;
import java.security.Key;
import java.security.Security;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static nl.booleans.oidc.yes.rcs.utils.RCSUtils.getDecrypter;
import static nl.booleans.oidc.yes.rcs.utils.RCSUtils.isHMAC;
import static nl.booleans.oidc.yes.rcs.utils.RCSUtils.parseJwt;

public class ConsentHandler {
    private JWT jwt;
    private final String jwksUri;
    private final String keyAlias;
    private final String keystorePath;
    private final String keyPass;
    private final String storePass;
    private final String issuer;
    private final Boolean encryptResponse;
    private final JwtHandler jwtHandler;


    /**
     * Load the in-memory DAO for saving consent. Lost upon JVM exit. Please implement your own persistence layer!
     */
    ConsentDao consentDao = ConsentDao.instance;


    /**
     * Construct a new ConsentHandler with:
     *
     * @param jwtString
     * @param jwksUri
     * @param keystorePath
     * @param keyAlias
     * @param keyPass
     * @param storePass
     * @param encryptResponse
     */
    public ConsentHandler(String jwtString, String jwksUri, String keystorePath, String keyAlias, String keyPass, String storePass, Boolean encryptResponse, String issuer) {
        Security.addProvider(new BouncyCastleProvider());
        this.jwksUri = jwksUri;
        this.keystorePath = keystorePath;
        this.keyAlias = keyAlias;
        this.keyPass = keyPass;
        this.storePass = storePass;
        this.jwt = parseJwt(jwtString);
        this.encryptResponse = encryptResponse;
        this.issuer = issuer;
        this.jwtHandler = new JwtHandler(this.keystorePath, this.keyAlias, this.storePass, this.keyPass, this.jwksUri);
    }


    /**
     * Returns a JWT object that has been verified and decrypted (if encrypted)
     *
     * @return
     * @throws DecryptionException
     * @throws InvalidJwt
     */
    public JWT getConsentRequest() throws DecryptionException, InvalidJwt {
        JWTClaimsSet claimsSet = null;
        if (this.jwt instanceof PlainJWT) {
            try {
                PlainJWT plainObject = (PlainJWT) this.jwt;

                ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                claimsSet = jwtProcessor.process(plainObject, null);

                return plainObject;
            } catch (JOSEException | BadJOSEException bse) {
                throw new InvalidJwt();
            }
        } else if (this.jwt instanceof SignedJWT) {

            SignedJWT jwsObject = (SignedJWT) this.jwt;
            JWKSource keySource = jwtHandler.getRemoteJWKSource();
            JWSKeySelector keySelector = new JWSVerificationKeySelector(jwsObject.getHeader().getAlgorithm(), keySource);

            try {
                if (isHMAC(jwsObject.getHeader().getAlgorithm())) {
                    System.out.println("the OIDC token is signed with HMAC, but no support for symmetric encryption is currently included.");
                } else {
                    ConfigurableJWTProcessor jwtProcessor = new DefaultJWTProcessor();
                    jwtProcessor.setJWSKeySelector(keySelector);
                    claimsSet = jwtProcessor.process(jwsObject, null);
                }
                return jwsObject;
            } catch (JOSEException | BadJOSEException je) {
                System.out.println("Caught exception while verifying signed JWT: "+je.getMessage());
            }

        } else if (this.jwt instanceof EncryptedJWT) {
            try {
                EncryptedJWT jweObject = (EncryptedJWT) this.jwt;
                JWKSource keySource = jwtHandler.getLocalJWKSource();
                JWEDecryptionKeySelector keySelect = new JWEDecryptionKeySelector(jweObject.getHeader().getAlgorithm(), jweObject.getHeader().getEncryptionMethod(), keySource);

                List<Key> possibleKeys = keySelect.selectJWEKeys(
                        new JWEHeader.Builder(
                                jweObject.getHeader().getAlgorithm(),
                                jweObject.getHeader().getEncryptionMethod()
                        )
                                .keyID(jweObject.getHeader().getKeyID())
                                .build(),
                        null);

                if (possibleKeys.size() > 1) {
                    System.out.println("multiple keys found for encryption method " + jweObject.getHeader().getAlgorithm().getName());
                } else if (possibleKeys.size() == 0) {
                    System.out.println("no keys found for encryption method " + jweObject.getHeader().getAlgorithm().getName());
                }

                try {
                    JWEDecrypter decrypter = getDecrypter(possibleKeys.get(0));
                    jweObject.decrypt(decrypter);
                } catch (JOSEException jse) {
                    throw new DecryptionException();
                }

                SignedJWT signedJWT = jweObject.getPayload().toSignedJWT();

                this.jwt = signedJWT;
                return this.getConsentRequest();
            } catch (KeySourceException kse) {
                System.out.println("caught exception while decrypting JWT: "+kse.getMessage());
            }
        }
        return null;
    }


    /**
     *
     * @param parsedJWT
     * @param originalJWT
     * @return
     */
    public String getConsentResponse(JWT parsedJWT, JWT originalJWT) {
        String consentResponseJwt = null;
        try {
            JWK match = jwtHandler.getLocalMatchingJWK();
            JWSSigner signer = new RSASSASigner((RSAKey)match);

            Boolean consentDecision = true;
            String username = this.getUsername(parsedJWT);

            Set<String> scopeSet = new HashSet<>();
            JSONObject jsonScopes = (JSONObject)parsedJWT.getJWTClaimsSet().getClaim("scopes");

            for (Map.Entry mapEntry : jsonScopes.entrySet()) {
                String scopeName = (String) mapEntry.getKey();
                if (consentDao.hasConsented(username, scopeName)) {
                    scopeSet.add(scopeName);
                }else{
                    consentDecision = false;
                }
            }

            Set<String> claimsSet = new HashSet<>();
            JSONObject jsonClaims = (JSONObject)parsedJWT.getJWTClaimsSet().getClaim("claims");

            for (String requestedOps : jsonClaims.keySet()) {
                JSONObject claim = (JSONObject) jsonClaims.get(requestedOps);

                for (Map.Entry<String, Object> claimEntry : claim.entrySet()) {
                    if (consentDao.hasConsented(username, claimEntry.getKey())) {
                        claimsSet.add(claimEntry.getKey());
                    } else {
                        System.err.println("no consent has been granted for claim " + claimEntry.getKey());
                        consentDecision = false;
                    }
                }
            }

            JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
                    .audience(parsedJWT.getJWTClaimsSet().getIssuer())
                    .issueTime(new Date(new Date().getTime()))
                    .issuer(this.issuer)
                    .claim("decision", consentDecision)
                    .claim("clientId", parsedJWT.getJWTClaimsSet().getClaim("clientId"))
                    .claim("csrf", parsedJWT.getJWTClaimsSet().getClaim("csrf"))
                    .claim("scopes", scopeSet)
                    .claim("claims", claimsSet)
                    .claim("save_consent", true)
                    .expirationTime(new Date(new Date().getTime() + (60 * 1000))) // TODO: make configurable
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                        .keyID(match.getKeyID())
                        .build(),
                    jwtClaimsSet
            );

            signedJWT.sign(signer);

            consentResponseJwt = signedJWT.serialize();

            // Encrypt this JWT in case encryption is enabled
            if (this.encryptResponse) {
                JWKSet remoteSet = jwtHandler.getRemoteJWKSet();

                JWEAlgorithm algorithm = null;
                try {
                    algorithm = ((EncryptedJWT) originalJWT).getHeader().getAlgorithm();
                } catch (ClassCastException cce) {
                    // System.err.println("Original JWT was not an EncryptedJWT, setting algorithm to default");
                    algorithm = JWEAlgorithm.RSA_OAEP_256;
                }

                EncryptionMethod encryptionMethod = null;
                try {
                    encryptionMethod = ((EncryptedJWT) originalJWT).getHeader().getEncryptionMethod();
                } catch (ClassCastException cce) {
                    // System.err.println("Original JWT was not an EncryptedJWT, setting encryption method to default");
                    encryptionMethod = EncryptionMethod.A128GCM;
                }

                List<JWK> matches = new JWKSelector(
                        new JWKMatcher.Builder()
                                .keyType(KeyType.RSA)
                                .algorithm(algorithm)
                                .keyUse(KeyUse.ENCRYPTION)
                                .build()
                ).select(remoteSet);

                // Encrypt with the recipient's public key
                if (matches.size() == 1) {
                    RSAKey matchingKey = (RSAKey) matches.get(0).toPublicJWK();

                    JWEObject jweObject = new JWEObject(
                            new JWEHeader.Builder(algorithm, encryptionMethod)
                                    .contentType("JWT") // required to indicate nested JWT
                                    .keyID(matchingKey.getKeyID())
                                    .build(),
                            new Payload(signedJWT));

                    jweObject.encrypt(new RSAEncrypter(matchingKey));
                    consentResponseJwt = jweObject.serialize();

                }else if (matches.size() == 0) {
                    System.err.println("Encrypted consent_response requested, but no public key found to encrypt with. Not returning a valid JWT.");
                    consentResponseJwt = null;
                }else{
                    System.err.println("Encrypted consent_response requested, but multiple keys found to encrypt with. Cannot choose - not returning a valid JWT.");
                    consentResponseJwt = null;
                }
            }
        } catch (ParseException | JOSEException e) {
            System.err.println("caught exception in getConsentResponse: "+e.getMessage());
            e.printStackTrace();
        }

        return consentResponseJwt;
    }


    /**
     *
     * @param postData
     * @return
     */
    public String persistConsent(MultivaluedMap<String, String> postData) {
        JWT consentRequestJwt = null;
        Map<String, Object> claimsFromJWT = new HashMap<>();

        try {
            consentRequestJwt = this.getConsentRequest();
            claimsFromJWT = consentRequestJwt.getJWTClaimsSet().getClaims();
        } catch (DecryptionException | ParseException | InvalidJwt e) {
            System.out.println("Caught exception while getting the claims from the JWT: "+e.getMessage());
        }

        if (consentRequestJwt != null) {
            String username = this.getUsername(consentRequestJwt);

            if (username != null) {
                Map<String, Object> claimsMap = (Map<String, Object>)claimsFromJWT.get("claims");
                Map<String, Object> scopesMap = (Map<String, Object>)claimsFromJWT.get("scopes");

                if (!this.haveConsentForAllScopes(username, scopesMap)) {
                    this.persistScopes(scopesMap, postData, username);
                }
                if (!this.haveConsentForAllClaims(username, claimsMap)) {
                    this.persistClaims(claimsMap, postData, username);
                }
            }
        }
        return null;
    }


    /**
     * Extract the username from the parsed JWT that is generated based upon the consent_request
     *
     * @param consentRequest
     * @return
     */
    public String getUsername(JWT consentRequest) {
        String username = null;
        try {
            username = (String)consentRequest.getJWTClaimsSet().getClaims().get("username");
        } catch (ParseException e) {
            e.printStackTrace();
        }
        return username;
    }


    /**
     * Returns a list of already consented scopes/claims
     *
     * @param username
     * @return
     */
    public Map<String, Consent> getPersistedScopesAndClaims(String username) {
        Map<String, Consent> existingConsent = consentDao.getAllConsent(username);
        return existingConsent;
    }


    /**
     * Determine whether all consent has already been given for the scopes in the consent_request.
     *
     * @param username - the username for this request
     * @param scopeData - a map containing the requested scopes
     * @return true if all scopes and claims have been previously consented to
     */
    public Boolean haveConsentForAllScopes(String username, Map<String, Object> scopeData) {
        List<String> consentList = this.getConsentScopeList(username, scopeData);
        for (String scope : scopeData.keySet()) {
            if (!consentList.contains(scope)) {
                return false;
            }
        }
        return true;
    }


    /**
     * Determine whether all consent has already been given for the claims in the consent_request.
     *
     * @param username - the username for this request
     * @param claimData - a map containing the requested claims
     * @return true if all scopes and claims have been previously consented to
     */
    public Boolean haveConsentForAllClaims(String username, Map<String, Object> claimData) {
        List<String> consentList = this.getConsentClaimList(username, claimData);
        for (String ops : claimData.keySet()) {
            JSONObject claim = (JSONObject)claimData.get(ops);
            for (Map.Entry<String, Object> claimEntry : claim.entrySet()) {
                if (!consentList.contains(claimEntry.getKey())) {
                    return false;
                }
            }
        }
        return true;
    }


    /**
     *
     * @param username
     * @param scopeMap
     * @return
     */
    private List<String> getConsentScopeList(String username, Map<String, Object> scopeMap) {
        List<String> consented = new ArrayList<>();
        if (scopeMap != null && scopeMap.size() > 0) {
            for (String consentName : scopeMap.keySet()) {
                if (consentDao.hasConsented(username, consentName)) {
                    consented.add(consentName);
                }
            }
        }else{
            System.out.println("List does not contain any scopes, unable to determine consent.");
        }
        return consented;
    }


    /**
     *
     * @param username
     * @param claimMap
     * @return
     */
    private List<String> getConsentClaimList(String username, Map<String, Object> claimMap) {
        List<String> consented = new ArrayList<>();
        if (claimMap.size() > 0) {
            for (String ops : claimMap.keySet()) {
                JSONObject claim = (JSONObject)claimMap.get(ops);
                for (Map.Entry<String, Object> claimEntry : claim.entrySet()) {
                    if (consentDao.hasConsented(username, claimEntry.getKey())) {
                        consented.add(claimEntry.getKey());
                    }
                }
            }
        }else{
            System.out.println("List does not contain any claims, unable to determine consent.");
        }
        return consented;
    }


    /**
     * Persists consented scopes to the DAO
     *
     * @param scopeData - the scopes as provided through the consent_request from AM
     * @param postData - the POST data as sent to the endpoint, for determining which fields were selected for consent
     * @param username - the validated username as provided through the consent_request from AM
     * @return
     */
    private void persistScopes(Map<String, Object> scopeData, MultivaluedMap<String, String> postData, String username) {
        for (String claimName : scopeData.keySet()) {
            if (postData.get(claimName) != null) {
                if (!consentDao.hasConsented(username, claimName)) {
                    Consent consent = new Consent()
                            .setConsentDate(new Date(new Date().getTime()))
                            .setConsentedClaim(claimName)
                            .setConsentedClaimDisplay((String)scopeData.get(claimName));
                    consentDao.saveConsent(username, consent);
                }
            }
        }
    }


    /**
     * Persists consented claims to the DAO
     *
     * @param claimData - the claims as provided through the consent_request from AM
     * @param postData - the POST data as sent to the endpoint, for determining which fields were selected for consent
     * @param username - the validated username as provided through the consent_request from AM
     * @return
     */
    private void persistClaims(Map<String, Object> claimData, MultivaluedMap<String, String> postData, String username) {
        for (String ops : claimData.keySet()) {
            JSONObject claim = (JSONObject)claimData.get(ops);

            for (Map.Entry<String, Object> claimEntry : claim.entrySet()) {
                if (postData.get(claimEntry.getKey()) != null) {
                    if (!consentDao.hasConsented(username, claimEntry.getKey())) {
                        Consent consent = new Consent()
                                .setConsentDate(new Date(new Date().getTime()))
                                .setConsentedClaim(claimEntry.getKey());
                        consentDao.saveConsent(username, consent);
                    }
                }
            }
        }
    }
}
