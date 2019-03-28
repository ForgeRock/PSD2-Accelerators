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
package org.forgerock.openam.oauth2;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.iplanet.am.sdk.AMHashMap;
import com.iplanet.am.util.SystemProperties;
import com.iplanet.dpro.session.SessionException;
import com.iplanet.dpro.session.TokenRestriction;
import com.iplanet.dpro.session.service.SessionService;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.iplanet.sso.SSOTokenManager;
import com.sun.identity.authentication.util.ISAuthConstants;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.AMIdentityRepository;
import com.sun.identity.idm.IdRepoException;
import com.sun.identity.idm.IdSearchControl;
import com.sun.identity.idm.IdSearchResults;
import com.sun.identity.idm.IdType;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.shared.Constants;
import com.sun.identity.shared.datastruct.CollectionHelper;
import com.sun.identity.shared.debug.Debug;
import com.sun.identity.sm.DNMapper;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceConfig;
import com.sun.identity.sm.ServiceConfigManager;
import org.forgerock.json.JsonValue;
import org.forgerock.oauth2.core.AccessToken;
import org.forgerock.oauth2.core.ClientRegistration;
import org.forgerock.oauth2.core.OAuth2ProviderSettings;
import org.forgerock.oauth2.core.OAuth2ProviderSettingsFactory;
import org.forgerock.oauth2.core.OAuth2Request;
import org.forgerock.oauth2.core.ScopeValidator;
import org.forgerock.oauth2.core.Token;
import org.forgerock.oauth2.core.UserInfoClaims;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.InvalidRequestException;
import org.forgerock.oauth2.core.exceptions.InvalidScopeException;
import org.forgerock.oauth2.core.exceptions.NoUserExistsException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.oauth2.core.exceptions.ServerException;
import org.forgerock.oauth2.core.exceptions.UnauthorizedClientException;
import org.forgerock.openam.agent.TokenRestrictionResolver;
import org.forgerock.openam.auth.nodes.yes.VerifiedPersonDataCollectorNode;
import org.forgerock.openam.oauth2.yes.claims.VerifiedPersonData;
import org.forgerock.openam.oauth2.yes.plugins.PluginWrapper;
import org.forgerock.openam.oauth2.yes.utils.MediationRecord;
import org.forgerock.openam.oauth2.yes.utils.ScopeToClaimsMapper;
import org.forgerock.openam.scripting.ScriptEvaluator;
import org.forgerock.openam.scripting.ScriptObject;
import org.forgerock.openam.scripting.SupportedScriptingLanguage;
import org.forgerock.openam.scripting.service.ScriptConfiguration;
import org.forgerock.openam.scripting.service.ScriptingServiceFactory;
import org.forgerock.openam.utils.CollectionUtils;
import org.forgerock.openam.utils.OpenAMSettings;
import org.forgerock.openam.utils.OpenAMSettingsImpl;
import org.forgerock.openidconnect.Claim;
import org.forgerock.openidconnect.Claims;
import org.forgerock.openidconnect.OpenIDTokenIssuer;
import org.forgerock.openidconnect.OpenIdConnectClientRegistration;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.restlet.Request;
import org.restlet.ext.servlet.ServletUtils;

import javax.inject.Inject;
import javax.inject.Named;
import javax.script.Bindings;
import javax.script.ScriptException;
import javax.script.SimpleBindings;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.AccessController;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static org.forgerock.json.JsonValue.field;
import static org.forgerock.json.JsonValue.fieldIfNotNull;
import static org.forgerock.json.JsonValue.json;
import static org.forgerock.json.JsonValue.object;
import static org.forgerock.oauth2.core.Utils.splitScope;
import static org.forgerock.oauth2.core.Utils.stringToList;
import static org.forgerock.openam.audit.context.AuditRequestContext.getAuditRequestContext;
import static org.forgerock.openam.oauth2.OAuth2Constants.JWTTokenParams.FORGEROCK_CLAIMS;
import static org.forgerock.openam.oauth2.OAuth2Constants.Params.OPENID;
import static org.forgerock.openam.oauth2.OAuth2Constants.TokenEndpoint.CLIENT_CREDENTIALS_GRANT_TYPE;
import static org.forgerock.openam.oauth2.yes.utils.ScopeToClaimsMapper.getAllRequestedClaims;
import static org.forgerock.openam.scripting.ScriptConstants.EMPTY_SCRIPT_SELECTION;
import static org.forgerock.openam.scripting.ScriptConstants.OIDC_CLAIMS_NAME;
import static org.forgerock.openam.session.SessionUtils.getAdminToken;


public class VerifiedPersonScopeValidator implements ScopeValidator {
    private static final String MULTI_ATTRIBUTE_SEPARATOR = ",";
    private static final String DEFAULT_TIMESTAMP = "0";
    private static final DateFormat TIMESTAMP_DATE_FORMAT = new SimpleDateFormat("yyyyMMddhhmmss");
    private static final String ADVANCED_SERVER_CONFIG_PROPERTY = "org.forgerock.openam.oauth2.VerifiedPersonDataConfig";
    private final OAuth2ProviderSettingsFactory providerSettingsFactory;
    private final Debug logger = Debug.getInstance("VerifiedPersonDataScopeValidator");
    private final IdentityManager identityManager;
    private final OpenIDTokenIssuer openIDTokenIssuer;
    private final OpenAMSettings openAMSettings;
    private final ScriptEvaluator scriptEvaluator;
    private final ScriptingServiceFactory scriptingServiceFactory;
    private final TokenRestrictionResolver agentValidator;
    private final SessionService sessionService;
    private final ObjectMapper mapper = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);


    /**
     * Constructs a new VerifiedPersonScopeValidator.
     *
     * @param identityManager An instance of the IdentityManager.
     * @param openIDTokenIssuer An instance of the OpenIDTokenIssuer.
     * @param providerSettingsFactory An instance of the CTSPersistentStore.
     * @param openAMSettings An instance of the OpenAMSettings.
     * @param scriptEvaluator An instance of the OIDC Claims ScriptEvaluator.
     * @param scriptingServiceFactory An instance of the ScriptingServiceFactory.
     * @param agentValidator An instance of {@code LDAPAgentValidator} used to retrieve the token restriction.
     * @param sessionService An instance of {@code SessionService}.
     */
    @Inject
    public VerifiedPersonScopeValidator(IdentityManager identityManager,
                                        OpenIDTokenIssuer openIDTokenIssuer,
                                        OAuth2ProviderSettingsFactory providerSettingsFactory,
                                        OpenAMSettings openAMSettings,
                                        @Named(OIDC_CLAIMS_NAME) ScriptEvaluator scriptEvaluator,
                                        ScriptingServiceFactory scriptingServiceFactory,
                                        TokenRestrictionResolver agentValidator,
                                        SessionService sessionService) {
        this.identityManager = identityManager;
        this.openIDTokenIssuer = openIDTokenIssuer;
        this.providerSettingsFactory = providerSettingsFactory;
        this.openAMSettings = openAMSettings;
        this.scriptEvaluator = scriptEvaluator;
        this.scriptingServiceFactory = scriptingServiceFactory;
        this.agentValidator = agentValidator;
        this.sessionService = sessionService;
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Set<String> validateAuthorizationScope(ClientRegistration client, Set<String> scope, OAuth2Request request) throws InvalidScopeException, ServerException {
        return validateScopes(scope, client.getDefaultScopes(), client.getAllowedScopes(), request);
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Set<String> validateAccessTokenScope(ClientRegistration client, Set<String> scope, OAuth2Request request) throws InvalidScopeException, ServerException {
        return validateScopes(scope, client.getDefaultScopes(), client.getAllowedScopes(), request);
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public Set<String> validateRefreshTokenScope(ClientRegistration clientRegistration, Set<String> requestedScope, Set<String> tokenScope, OAuth2Request request) throws ServerException, InvalidScopeException {
        return validateScopes(requestedScope, tokenScope, tokenScope, request);
    }


    /**
     *
     * @param ssoToken
     * @param sessionKey
     * @return
     */
    private Map getDataFromSession(SSOToken ssoToken, String sessionKey) {
        try {
            String scopeData = ssoToken.getProperties().get(sessionKey);
            JsonFactory factory = mapper.getFactory();
            JsonParser jsonParser = factory.createParser(scopeData);
            JsonNode node = mapper.readTree(jsonParser);
            return mapper.convertValue(node, Map.class);
        } catch (SSOException se) {
            logger.error("Caught SSOException while looking for sessionKey data. Message: "+se.getMessage());
            logger.message("Exception details: ",se);
        } catch (IOException ioe) {
            logger.error("Caught IOException while looking for sessionKey data "+sessionKey);
            logger.message("Exception details: ",ioe);
        } catch (NullPointerException npe) {
            logger.warning("No data in session for sessionKey "+sessionKey);
        }
        return Collections.EMPTY_MAP;
    }


    /**
     *
     * @param amIdentity
     * @param profileAttribute
     * @return
     */
    private Map<String, Object> getDataFromProfile(AMIdentity amIdentity, String profileAttribute) {
        final Map<String, Object> map = new HashMap<>();

        try {
            Set<String> attributes = amIdentity.getAttribute(profileAttribute);
            StringBuilder builder = new StringBuilder();
            if (CollectionUtils.isNotEmpty(attributes)) {
                Iterator<String> iter = attributes.iterator();
                while (iter.hasNext()) {
                    builder.append(iter.next());
                    if (iter.hasNext()) {
                        builder.append(MULTI_ATTRIBUTE_SEPARATOR);
                    }
                }
                map.put(profileAttribute, builder.toString());
            }
        } catch (IdRepoException ie) {
            logger.error("Unable to read attributes from profile for user "+amIdentity.getName()+": "+ie.getMessage());
        } catch (SSOException se) {
            logger.error("Unable to read attributes from profile for user "+amIdentity.getName()+": "+se.getMessage());
        }

        return map;
    }


    /**
     *
     * @param scopes
     * @return
     */
    private List<String> getVPDScopes(Set<String> scopes) {
        List<String> vpdScopes = new ArrayList<>();

        for (String scopeName : scopes) {
            if (ScopeToClaimsMapper.getScopeToClaimsMap().containsKey(scopeName)) {
                vpdScopes.add(scopeName);
            }else{
                logger.warning("getVPDScopes: scopeToClaimsMap does not contain scope "+scopeName);
            }
        }
        return vpdScopes;
    }


    /**
     *
     * @param claims
     * @return
     */
    private List<Claim> getVPDClaims(List<Claim> claims) {
        List<Claim> vpdClaims = new ArrayList<>();

        for (Claim claim : claims) {
            if (ScopeToClaimsMapper.getScopeToClaimsMap().containsKey(claim.getName())) {
                vpdClaims.add(claim);
            }else{
                logger.warning("getVPDClaims: scopeToClaimsMap does not contain claim "+claim.getName());
            }
        }

        return vpdClaims;
    }


    /**
     * Return a list of requested sub claims based on a claim name
     *
     * @param claimName
     * @return
     */
    private List<Claim> getAssociatedVPDClaims(String claimName) {
        try {
            List<Claim> definedClaims = ScopeToClaimsMapper.getScopeToClaimsMap().get(claimName);
            return definedClaims;
        } catch (Exception e) {
        }

        return Collections.EMPTY_LIST;
    }


    /**
     *
     * @param request
     * @param accessToken
     * @param userInfoClaims
     * @param vpdScopes
     * @param vpdClaims
     * @return
     */
    private UserInfoClaims getVPDDetails(OAuth2Request request, AccessToken accessToken, UserInfoClaims userInfoClaims, List<String> vpdScopes, List<Claim> vpdClaims) {
        if ((vpdScopes == null || vpdScopes.size() == 0) && (vpdClaims == null || vpdClaims.size() == 0)) {
            return userInfoClaims;
        }

        SSOToken ssoToken = getUsersSession(request);

        AMIdentity amIdentity;
        String realm;
        try {
            if (accessToken != null) {
                realm = accessToken.getRealm();
                amIdentity = getUsersIdentity(accessToken.getResourceOwnerId(), realm, request);
            } else {
                realm = DNMapper.orgNameToRealmName(ssoToken.getProperty(ISAuthConstants.ORGANIZATION));
                amIdentity = getUsersIdentity(ssoToken.getProperty(ISAuthConstants.USER_ID), realm, request);
            }

            for (String scopeName : vpdScopes) {
                try {
                    if (ssoToken != null) {
                        userInfoClaims.getValues().put(scopeName, this.getDataFromSession(ssoToken, scopeName));
                    } else {
                        logger.warning("Information for scope "+scopeName+" cannot be retrieved from the session, attempting to retrieve it from the profile");
                        Map<String, Object> profileData = this.getDataFromProfile(amIdentity, scopeName);
                        if (profileData != null && profileData.size() > 0) {
                            userInfoClaims.getValues().put(scopeName, profileData);
                        }else{
                            logger.warning("Unable to get profile information for scope "+scopeName+", contacting VPD service.");

                            VerifiedPersonData verifiedPersonData = this.getVerifiedPersonData(vpdScopes, null, amIdentity.getName(), realm);
                            Map convertedValue = mapper.convertValue(verifiedPersonData, Map.class);
                            userInfoClaims.getValues().put(scopeName, convertedValue);
                        }
                    }
                } catch (NullPointerException npe) {
                    logger.warning("No scope data in session for scope "+scopeName+": "+npe.getMessage());
                }
            }

            for (Claim claim : vpdClaims) {
                try {
                    if (ssoToken != null) {
                        userInfoClaims.getValues().put(claim.getName(), this.getDataFromSession(ssoToken, claim.getName()));
                    } else {
                        logger.warning("Information for claim "+claim.getName()+" cannot be retrieved from the session, attempting to retrieve it from the profile");
                        Map<String, Object> profileData = this.getDataFromProfile(amIdentity, claim.getName());
                        if (profileData != null && profileData.size() > 0) {
                            userInfoClaims.getValues().put(claim.getName(), profileData);
                        } else {
                            logger.warning("Unable to get profile information for claim "+claim.getName()+", contacting VPD service.");
                        }
                    }
                } catch (NullPointerException npe) {
                    logger.warning("No claim data in session for claim "+claim.getName());
                }
            }
        } catch (SSOException se) {
            logger.error("Unable to retrieve VPD information: "+se.getMessage());
        } catch (UnauthorizedClientException uce) {
            logger.error("Client unauthorized when retrieving VPD information: "+uce.getMessage());
        }

        return userInfoClaims;
    }


    /**
     * {@inheritDoc}
     */
    public UserInfoClaims getUserInfo(ClientRegistration clientRegistration, AccessToken accessToken, OAuth2Request request) throws UnauthorizedClientException, NotFoundException, ServerException, InvalidRequestException {
        List<Claim> providedClaims = new ArrayList<Claim>();
        Bindings scriptVariables = new SimpleBindings();
        SSOToken ssoToken = getUsersSession(request);
        Set<String> scopes;
        String realm;
        AMIdentity id;
        OAuth2ProviderSettings providerSettings = providerSettingsFactory.get(request);
        List<Claim> requestedClaimsValues = gatherRequestedClaims(providerSettings, request, accessToken);
        List<Claim> requestedNestedClaims = gatherRequestedNestedClaims(providerSettings, request, accessToken, "claims");
        List<Claim> requestedNestedVerification = gatherRequestedNestedClaims(providerSettings, request, accessToken, "verification");

        Map<String, List<Claim>> allNestedClaimsMap = new HashMap<>();
        allNestedClaimsMap.put("claims", requestedNestedClaims);
        allNestedClaimsMap.put("verification", requestedNestedVerification);

        try {
            if (accessToken != null) {
                realm = accessToken.getRealm();
                scopes = accessToken.getScope();
                id = getUsersIdentity(accessToken.getResourceOwnerId(), realm, request);
                addSubToResponseIfOpenIdConnect(clientRegistration, accessToken, providedClaims, providerSettings);
                providedClaims.add(new Claim(OAuth2Constants.JWTTokenParams.UPDATED_AT, getUpdatedAt(accessToken.getResourceOwnerId(), accessToken.getRealm(), request)));
            } else {
                realm = DNMapper.orgNameToRealmName(ssoToken.getProperty(ISAuthConstants.ORGANIZATION));
                id = getUsersIdentity(ssoToken.getProperty(ISAuthConstants.USER_ID), realm, request);
                String scopeStr = request.getParameter(OAuth2Constants.Params.SCOPE);
                scopes = splitScope(scopeStr);
            }

            scriptVariables.put(OAuth2Constants.ScriptParams.SCOPES, getScriptFriendlyScopes(scopes));
            scriptVariables.put(OAuth2Constants.ScriptParams.IDENTITY, id);
            scriptVariables.put(OAuth2Constants.ScriptParams.LOGGER, logger);
            scriptVariables.put(OAuth2Constants.ScriptParams.CLAIMS_LEGACY, providedClaimsToLegacyFormat(providedClaims));
            scriptVariables.put(OAuth2Constants.ScriptParams.CLAIMS, providedClaims);
            scriptVariables.put(OAuth2Constants.ScriptParams.SESSION, ssoToken);
            scriptVariables.put(OAuth2Constants.ScriptParams.REQUESTED_CLAIMS_LEGACY, requestedClaimsToLegacyFormat(requestedClaimsValues));
            scriptVariables.put(OAuth2Constants.ScriptParams.REQUESTED_CLAIMS, requestedClaimsValues);
            scriptVariables.put(OAuth2Constants.ScriptParams.CLAIMS_LOCALES, (Object)getScriptFriendlyClaimLocales(stringToList((String)request.getParameter("claims_locales"))));

            ScriptObject script = getOIDCClaimsExtensionScript(realm);

            try {
                UserInfoClaims userInfoClaims = scriptEvaluator.evaluateScript(script, scriptVariables);

                if (isAgentRequest(clientRegistration)) {
                    userInfoClaims = addRestrictedSSOTokenToUserInfoClaims(userInfoClaims, clientRegistration, realm, ssoToken);
                }else{
                    List<String> vpdScopes = this.getVPDScopes(scopes);

                    userInfoClaims = this.mergeUserInfoClaims(
                            userInfoClaims,
                            this.getVPDDetails(request, accessToken, userInfoClaims, vpdScopes, this.getVPDClaims(requestedClaimsValues))
                    );

                    try {
                        userInfoClaims = this.mergeUserInfoClaims(userInfoClaims, this.validateUserInfoResponse(accessToken, request, userInfoClaims, requestedClaimsValues, allNestedClaimsMap, vpdScopes));
                    } catch (InvalidRequestException ire) {
                        throw ire;
                    }
                }

                try {
                    JSONObject json = new JSONObject();
                    json.put("name", "access_token");
                    JSONArray array = new JSONArray();
                    JSONObject item = new JSONObject();
                    item.put("action", "token_retrieved");
                    item.put("token", accessToken.getTokenId());
                    item.put("scopes", accessToken.getScope());
                    array.put(item);
                    json.put("action_details", array);

                    MediationRecord mr = new MediationRecord(json);
                    mr.sendMediationRecord();
                } catch (JSONException jpe) {
                    logger.error("Unable to send mediation record: "+jpe.getMessage());
                }

                return userInfoClaims;
            } catch (ScriptException e) {
                InvalidRequestException oAuth2Exception = unwrapInvalidRequestException(e);
                if (oAuth2Exception != null) {
                    throw oAuth2Exception;
                }
                logger.message("Error running OIDC claims script", e);
                throw new ServerException("Error running OIDC claims script: " + e.getMessage());
            }
        } catch (SSOException e) {
            throw new NotFoundException(e.getMessage());
        }
    }


    /**
     * Check if a specific claim is part of a list of VPD claims
     *
     * @param claims - List<Claim> object with VPD claims
     * @param claimName - name of the claim to verify
     * @return - Boolean indicating if it has been found or not.
     */
    private Boolean isClaimRequestAllowed(List<Claim> claims, String claimName) {
        for (Claim claim : claims) {
            if (claimName.equalsIgnoreCase(claim.getName())) {
                return true;
            }
        }
        return false;
    }


    /**
     * Merge data from multiple userInfoClaims together
     *
     * @param userInfoClaims UserInfoClaims object that will be expanded
     * @param mergeUserInfoClaims UserInfoClaims object that will be merged
     * @return UserInfoClaims with merged data.
     */
    private UserInfoClaims mergeUserInfoClaims(UserInfoClaims userInfoClaims, UserInfoClaims mergeUserInfoClaims) {
        Set<Map.Entry<String, Object>> values = mergeUserInfoClaims.getValues().entrySet();
        for (Map.Entry<String, Object> claimEntry : values) {
            userInfoClaims.getValues().put(claimEntry.getKey(), claimEntry.getValue());
        }
        return userInfoClaims;
    }


    /**
     * Return if a specific claim is within the required limit. Currently only handles the date for the verification data.
     *
     * @param claimData
     * @param claims
     * @param claimName
     * @param rawJson
     * @return
     */
    private Boolean validateVerificationClaim(Object claimData, List<Claim> claims, String claimName, JSONObject rawJson) {
        switch (claimName) {
            case "date":
                Claim claim = getClaimFromList(claims, claimName);
                if (claim != null && claim.isEssential()) {
                    try {
                        long maxAge = Long.parseLong(rawJson.getString("max_age"));
                        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd", Locale.getDefault());
                        long verificationDateMillis = df.parse(claimData.toString()).getTime();
                        long currentMillis = new Date().getTime();

                        if (currentMillis - (maxAge * 1000) > verificationDateMillis) {
                            logger.error("Data has expired, cannot fulfil requirement!");
                            return false;
                        } else {
                            return true;
                        }
                    } catch (ParseException pe) {
                        logger.error("Unable to parse date: "+pe.getMessage());
                        logger.message("Associated stacktrace: ",pe);
                    } catch (JSONException ex) {
                        logger.error("Unable to parse raw json: "+ex.getMessage());
                        logger.message("Associated stacktrace: ",ex);
                    }
                }
                return false;
            default:
                return true;
        }
    }


    /**
     *
     * @param allowedClaims
     * @param actualClaims
     * @return
     */
    private Boolean validRequestedClaims(List<Claim> allowedClaims, List<Claim> actualClaims) {
        Boolean found = false;

        if (actualClaims.size() == 0) {
            return true;
        }

        for (Claim actualClaim : actualClaims) {
            for (Claim allowedClaim : allowedClaims) {
                if (allowedClaim.getName().equalsIgnoreCase(actualClaim.getName())) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                logger.error("claim "+actualClaim.getName()+" not found in list of allowed claims");
                return false;
            }
        }
        return found;
    }


    /**
     * Returns the Claim object from a list of claims by its name
     *
     * @param claims - List<Claim> containing the claims to select from
     * @param claimName - String containing the name of the claim to return
     * @return - Claim object
     */
    private Claim getClaimFromList(List<Claim> claims, String claimName) {
        for (Claim claim : claims) {
            if (claim.getName().equalsIgnoreCase(claimName)) {
                return claim;
            }
        }
        return null;
    }


    /**
     * Return a JSON representation from the original requested JSON
     *
     * @param accessToken
     * @param request
     * @param claimName
     * @param nestedKey
     * @param fieldName
     * @return
     */
    private JSONObject getOrgClaimContents(AccessToken accessToken, OAuth2Request request, String claimName, String nestedKey, String fieldName) {
        try {
            JSONObject object = new JSONObject(accessToken.getClaims());
            return object.getJSONObject(
                    this.getRequestInfoType(request))
                    .getJSONObject(claimName)
                    .getJSONObject(nestedKey)
                    .getJSONObject(fieldName);
        }catch (JSONException je) {
        }
        return null;
    }


    /**
     * Returns the trackingId for this request
     *
     * @return String with transactionId value from the audit request context
     */
    private String getTrackingIdentifier() {
        return getAuditRequestContext().getTransactionIdValue();
    }


    /**
     * Checks if the transaction_id claim is requested based on the claims
     *
     * @param claims List<Claim> to check against
     * @return Boolean indicating whether the transaction_id was requested or not.
     */
    private Boolean shouldAddTransactionIdForClaims(List<Claim> claims) {
        if (claims == null || claims.size() == 0) {
            return false;
        }
        for (Claim claim : claims) {
            if (claim.getName().equalsIgnoreCase("https://www.yes.com/claims/transaction_id")) {
                return true;
            }
        }

        return false;
    }


    /**
     * Checks if the transaction_id claim is requested based on the scopes
     *
     * @param scopes List<String> of scopes to check against
     * @return Boolean indicating whether the transaction_id was requested or not.
     */
    private Boolean shouldAddTransactionIdForScopes(List<String> scopes) {
        if (scopes == null || scopes.size() == 0) {
            return false;
        }

        for (String scopeName : scopes) {
            List<Claim> scopeToClaimsList = this.getAssociatedVPDClaims(scopeName);
            Boolean evalResult = this.shouldAddTransactionIdForClaims(scopeToClaimsList);
            logger.message("evalResult based on scope " + scopeName + ": " + evalResult);
            if (evalResult) {
                return true;
            }
        }

        return false;
    }


    /**
     * Adds a transaction_id if so requested
     *
     * @param uiClaims
     * @param keyName
     * @param userInfoClaimsName
     * @return
     */
    private UserInfoClaims addTransactionId(UserInfoClaims uiClaims, String keyName, String userInfoClaimsName) {
        LinkedHashMap trackingMap = new LinkedHashMap();
        LinkedHashMap trackingSubMap = new LinkedHashMap();
        String trackingId = this.getTrackingIdentifier();
        trackingMap.put("transaction_id", trackingId);
        trackingSubMap.put(keyName, trackingMap);

        Object currentUIClaimDetails = uiClaims.getValues().get(userInfoClaimsName);
        if (currentUIClaimDetails instanceof LinkedHashMap) {
            LinkedHashMap currentClaimDetails = (LinkedHashMap) currentUIClaimDetails;
            if (currentClaimDetails != null) {
                LinkedHashMap currentClaimPartDetails = (LinkedHashMap) currentClaimDetails.get(keyName);
                if (currentClaimPartDetails != null) {
                    currentClaimPartDetails.put("transaction_id", trackingId);
                } else {
                    ((LinkedHashMap) uiClaims.getValues().get(userInfoClaimsName)).put(keyName, trackingSubMap);
                }
            } else {
                LinkedHashMap uiClaimsTree = new LinkedHashMap();
                uiClaimsTree.put(keyName, trackingSubMap);
                uiClaims.getValues().put(userInfoClaimsName, uiClaimsTree);
            }
        }
        return uiClaims;
    }


    /**
     *
     * @param accessToken
     * @param request
     * @param claimName
     * @param nestedKey
     * @return
     */
    private Boolean hasUnspecifiedClaimData(AccessToken accessToken, OAuth2Request request, String claimName, String nestedKey) {
        try {
            JSONObject object = new JSONObject(accessToken.getClaims());
            JSONObject jsonObject = object.getJSONObject(
                    this.getRequestInfoType(request))
                    .getJSONObject(claimName);

            if (jsonObject.has(nestedKey)) {
                try {
                    Object item = jsonObject.get(nestedKey);
                    if (item == null || item.toString().equalsIgnoreCase("null")) {
                        return true;
                    }
                } catch (JSONException je) {
                }
            } else {
                return false;
            }
        }catch (NullPointerException npe) {
        }catch (JSONException je) {
        }
        return false;
    }


    /**
     * Validate the userinfo response
     *
     * @param token AccessToken object
     * @param request OAuth2Request object
     * @param uiClaims UserInfoClaims object
     * @param reqClaims List<Claim> containing the requested claims
     * @param nestedClaims List<Claim> containing the requested nested claims
     * @return UserInfoClaims object
     * @throws InvalidRequestException
     */
    private UserInfoClaims validateUserInfoResponse(AccessToken token, OAuth2Request request, UserInfoClaims uiClaims, List<Claim> reqClaims, Map<String, List<Claim>> nestedClaims, List<String> vpdScopes)
            throws InvalidRequestException {

        for (String userInfoClaimsName : uiClaims.getValues().keySet()) {
            if (vpdScopes.contains(userInfoClaimsName)) {
                if (this.shouldAddTransactionIdForScopes(vpdScopes)) {
                    uiClaims = this.addTransactionId(uiClaims, "claims", userInfoClaimsName);
                }
            }

            for (String keyName : nestedClaims.keySet()) {
                List<Claim> allowedVpdNestedClaims = this.getAssociatedVPDClaims(userInfoClaimsName);
                Boolean shouldAddTransactionId = this.shouldAddTransactionIdForClaims(allowedVpdNestedClaims);
                if (!shouldAddTransactionId) {
                    shouldAddTransactionId = this.shouldAddTransactionIdForClaims(nestedClaims.get(keyName));
                }

                if (!shouldAddTransactionId) {
                    shouldAddTransactionId = this.shouldAddTransactionIdForScopes(vpdScopes);
                }

                if (keyName.equalsIgnoreCase("claims")) {
                    if (this.hasUnspecifiedClaimData(token, request, userInfoClaimsName, keyName)) {
                        Object userInfoClaimData = uiClaims.getValues().get(userInfoClaimsName);
                        if (userInfoClaimData instanceof LinkedHashMap) {
                            if (uiClaims.getValues().get(userInfoClaimsName) != null) {
                                ((LinkedHashMap) uiClaims.getValues().get(userInfoClaimsName)).put(keyName, ((LinkedHashMap)userInfoClaimData).get(keyName));
                            } else {
                                LinkedHashMap uiClaimsTree = new LinkedHashMap();
                                uiClaimsTree.put(keyName, ((LinkedHashMap)userInfoClaimData).get(keyName));
                                uiClaims.getValues().put(userInfoClaimsName, uiClaimsTree);
                            }
                        }

                        if (shouldAddTransactionId) {
                            uiClaims = this.addTransactionId(uiClaims, keyName, userInfoClaimsName);
                        }
                    } else if (this.isClaimRequestAllowed(reqClaims, userInfoClaimsName)) {
                        LinkedHashMap userInfoClaimDetails = (LinkedHashMap) uiClaims.getValues().get(userInfoClaimsName);
                        LinkedHashMap<String, Object> newValues = new LinkedHashMap<>();

                        // this contains the details from the UserInfoClaims
                        LinkedHashMap<String, Object> individualClaimsMap = (LinkedHashMap) userInfoClaimDetails.get(keyName);

                        if (!validRequestedClaims(allowedVpdNestedClaims, nestedClaims.get(keyName))) {
                            throw new InvalidRequestException("invalid_request");
                        }

                        if (nestedClaims.get(keyName).size() != 0 && individualClaimsMap != null && individualClaimsMap.size() > 0) {
                            for (String individualClaimName : individualClaimsMap.keySet()) {
                                if (this.isClaimRequestAllowed(nestedClaims.get(keyName), individualClaimName)) {
                                    if (this.isClaimRequestAllowed(allowedVpdNestedClaims, individualClaimName)) {
                                        newValues.put(individualClaimName, individualClaimsMap.get(individualClaimName));
                                    }else{
                                        logger.error("claim "+individualClaimName+" was requested but is not valid for this request");
                                    }
                                }
                            }

                            LinkedHashMap currentValues = (LinkedHashMap) ((LinkedHashMap) uiClaims.getValues().get(userInfoClaimsName)).get(keyName);
                            if (currentValues.size() > 0) {
                                ((LinkedHashMap) uiClaims.getValues().get(userInfoClaimsName)).put(keyName, newValues);
                            }else {
                                LinkedHashMap uiClaimsTree = new LinkedHashMap();
                                uiClaimsTree.put(keyName, newValues);
                                uiClaims.getValues().put(userInfoClaimsName, uiClaimsTree);
                            }
                        }
                        if (shouldAddTransactionId) {
                            uiClaims = this.addTransactionId(uiClaims, keyName, userInfoClaimsName);
                        }
                    }
                } else if (keyName.equalsIgnoreCase("verification")) {
                    Object userInfoClaimDetailsObject = uiClaims.getValues().get(userInfoClaimsName);
                    if (userInfoClaimDetailsObject instanceof LinkedHashMap) {
                        LinkedHashMap userInfoClaimDetails = (LinkedHashMap) uiClaims.getValues().get(userInfoClaimsName);
                        LinkedHashMap<String, Object> individualClaimsMap = (LinkedHashMap) userInfoClaimDetails.get(keyName);

                        if (nestedClaims.get(keyName).size() != 0 && individualClaimsMap != null && individualClaimsMap.size() > 0) {
                            for (String individualClaimName : individualClaimsMap.keySet()) {
                                JSONObject rawDetails = getOrgClaimContents(token, request, userInfoClaimsName, keyName, individualClaimName);
                                if (!validateVerificationClaim(individualClaimsMap.get(individualClaimName), nestedClaims.get(keyName), individualClaimName, rawDetails)) {
                                    throw new InvalidRequestException("unable_to_meet_requirement");
                                }
                            }
                        }

                        if (uiClaims.getValues().get(userInfoClaimsName) != null) {
                            ((LinkedHashMap) uiClaims.getValues().get(userInfoClaimsName)).put(keyName, (LinkedHashMap) userInfoClaimDetails.get(keyName));
                        }else{
                            LinkedHashMap uiClaimsTree = new LinkedHashMap();
                            uiClaimsTree.put(keyName, (LinkedHashMap) userInfoClaimDetails.get(keyName));
                            uiClaims.getValues().put(userInfoClaimsName, uiClaimsTree);
                        }
                    }
                }
            }
        }
        return uiClaims;
    }


    /**
     *
     * @param resourceOwnerId
     * @param realm
     * @param request
     * @return
     * @throws SSOException
     * @throws UnauthorizedClientException
     */
    private AMIdentity getUsersIdentity(String resourceOwnerId, String realm, OAuth2Request request) throws SSOException, UnauthorizedClientException {
        try {
            return identityManager.getResourceOwnerOrClientIdentity(request, resourceOwnerId, realm);
        } catch (NoUserExistsException e) {
            logger.message("No user exists for {} in realm {}", resourceOwnerId, realm);
            if (identityManager.isIgnoredProfile(realm)) {
                logger.message("User profile set to ignore, 'no user' result is valid.");
                return null;
            }
            throw e;
        }
    }


    /**
     * Retrieves the configuration for an instance of the VerifiedPersonDataCollectorNode inside the same realm.
     *
     * @param realm
     * @return
     */
    private Map<String, Set<String>> getAuthNodeConfig(String realm) {
        try {
            SSOToken token = getAdminToken();
            String serviceName = VerifiedPersonDataCollectorNode.class.getSimpleName();
            ServiceConfigManager configManager = new ServiceConfigManager(serviceName, token);

            ServiceConfig container = configManager.getOrganizationConfig(realm, null);

            String nodeId = null;
            Set<String> nodeInstances = container.getSubConfigNames();
            if (nodeInstances.size() == 0) {
                logger.error("no instances of the VerifiedPersonDataCollectorNode found in realm "+realm+", cannot continue.");
            }else if (nodeInstances.size() > 1) {
                logger.error("multiple instances of the VerifiedPersonDataCollectorNode found in realm "+realm+", picking one");
                nodeId = nodeInstances.iterator().next();
            }else{
                nodeId = nodeInstances.iterator().next();
            }

            if (nodeId != null) {
                ServiceConfig nodeConfig = container.getSubConfig(nodeId);
                return nodeConfig.getAttributes();
            }

            // TODO: fallback to 'normal' configuration mode through advanced server settings.
        } catch (SMSException e) {
            logger.error("Unable to fetch configuration for the VerifiedPersonDataCollectorNode: "+e.getMessage());
            logger.message("Associated stacktrace: ",e);
        } catch (SSOException e) {
            logger.error("Unable to get an admin token to fetch the configuration: "+e.getMessage());
            logger.message("Associated stacktrace: ",e);
        }
        return Collections.EMPTY_MAP;
    }


    /**
     * Returns the configuration in the same format as authnode configuration from the advanced server properties.
     *
     * @param realm String realmname
     * @return Map<String, Set<String>> containing the configuration data
     */
    private Map<String, Set<String>> getAdvancedServerConfig(String realm) {
        String configItem = SystemProperties.get(ADVANCED_SERVER_CONFIG_PROPERTY);
        JSONObject config;
        try {
            config = new JSONObject(configItem).getJSONObject(realm);
            Map<String, Set<String>> configData = new HashMap<>();

            for (int x = 0; x < config.names().length(); x++) {
                String keyname = config.names().getString(x);
                JSONArray data = (JSONArray)config.get(keyname);
                Set<String> itemCfg = new HashSet<>();
                for (int y = 0; y < data.length(); y++) {
                    Object details = data.get(y);
                    if (details instanceof String) {
                        itemCfg.add((String) details);
                    }else if (details instanceof Integer) {
                        itemCfg.add(String.valueOf(details));
                    }else if (details instanceof Boolean) {
                        itemCfg.add(String.valueOf(details));
                    }
                }

                configData.put(keyname, itemCfg);
            }
            return configData;
        } catch (JSONException je) {
            logger.error("configuration for this scope validator is not valid JSON: "+ je);
        } catch (NullPointerException npe) {
            logger.error("configuration for this scope validator is not configured as property "+ADVANCED_SERVER_CONFIG_PROPERTY);
        }
        return Collections.EMPTY_MAP;
    }


    /**
     * Get VerifiedPersonData from a remote endpoint based on the configuration for the authentication node.
     *
     * @param scopes
     * @param claims
     * @param username
     * @return VerifiedPersonData object
     */
    private VerifiedPersonData getVerifiedPersonData(List<String> scopes, List<String> claims, String username, String realm) {
        Map<String, List<Claim>> requestedClaimsAndScopes = getAllRequestedClaims(scopes, claims);

        Map<String, Set<String>> pluginConfig = this.getAuthNodeConfig(realm);

        if (pluginConfig == null || pluginConfig.size() == 0) {
            pluginConfig = this.getAdvancedServerConfig(realm);
        }

        Map<String, String> injectedHeaders = new HashMap<>();
        injectedHeaders.put("Content-Type", "application/json");

        PluginWrapper pluginWrapper = new PluginWrapper(
                pluginConfig.get("remoteVPDService").iterator().next(),
                pluginConfig.get("httpMethod").iterator().next(),
                injectedHeaders,
                pluginConfig.get("pluginClass").iterator().next(),
                Integer.parseInt(pluginConfig.get("connectTimeout").iterator().next()),
                Integer.parseInt(pluginConfig.get("readTimeout").iterator().next())
        );
        return pluginWrapper.getVerifiedPersonData(requestedClaimsAndScopes, username);
    }


    /**
     * {@inheritDoc}
     */
    public Map<String, Object> evaluateScope(AccessToken accessToken) {
        final Map<String, Object> map = new HashMap<>();

        if (accessToken == null) {
            return map;
        }

        final Set<String> scopes = accessToken.getScope();
        if (scopes.isEmpty()) {
            return map;
        }

        final String resourceOwner = accessToken.getResourceOwnerId();
        final String clientId = accessToken.getClientId();
        final String realm = accessToken.getRealm();

        AMIdentity id = null;
        try {
            if (clientId != null && CLIENT_CREDENTIALS_GRANT_TYPE.equals(accessToken.getGrantType()) ) {
                id = identityManager.getClientIdentity(clientId, realm);
            } else if (resourceOwner != null) {
                id = identityManager.getResourceOwnerIdentity(resourceOwner, realm);
            }
        } catch (UnauthorizedClientException e) {
            logger.error("Unable to fetch the AMIdentity: "+e.getMessage());
            logger.message("Associated stacktrace: ",e);
        }
        if (id != null) {
            for (String scope : scopes) {
                try {
                    if (ScopeToClaimsMapper.getClaimsForScope(scope) != null) {
                        Map scopeProfileData = this.getDataFromProfile(id, scope);
                        if (scopeProfileData != null && scopeProfileData.size() != 0) {
                            map.put(scope, scopeProfileData);
                        }
                    }else {
                        Set<String> attributes = id.getAttribute(scope);
                        StringBuilder builder = new StringBuilder();
                        if (CollectionUtils.isNotEmpty(attributes)) {
                            Iterator<String> iter = attributes.iterator();
                            while (iter.hasNext()) {
                                builder.append(iter.next());
                                if (iter.hasNext()) {
                                    builder.append(MULTI_ATTRIBUTE_SEPARATOR);
                                }
                            }
                        }
                        map.put(scope, builder.toString());
                    }
                } catch (IdRepoException e) {
                    logger.error("Unable to retrieve attribute from datastore: "+e.getMessage());
                    logger.message("Associated stacktrace: ",e);
                } catch (SSOException e) {
                    logger.error("Unable to retrieve attribute from datastore: "+e.getMessage());
                    logger.message("Associated stacktrace: ",e);
                }
            }
        }
        return map;
    }


    /**
     * {@inheritDoc}
     */
    public Map<String, String> additionalDataToReturnFromAuthorizeEndpoint(Map<String, Token> tokens, OAuth2Request request) {
        return Collections.emptyMap();
    }


    /**
     * {@inheritDoc}
     */
    public void additionalDataToReturnFromTokenEndpoint(AccessToken accessToken, OAuth2Request request)
            throws ServerException, InvalidClientException, NotFoundException {
        final Set<String> scope = accessToken.getScope();

        if (scope != null && scope.contains(OPENID)) {
            final Map.Entry<String, Supplier<String>> tokenEntry = openIDTokenIssuer.issueToken(accessToken, request);
            if (tokenEntry != null) {
                accessToken.addExtraData(tokenEntry.getKey(), tokenEntry.getValue());
            }
        }

        try {
            JSONObject json = new JSONObject();
            json.put("name", "access_token");
            JSONArray array = new JSONArray();
            JSONObject item = new JSONObject();
            item.put("action", "token_retrieved");
            item.put("token", accessToken.getTokenId());
            item.put("scopes", accessToken.getScope());
            array.put(item);
            json.put("action_details", array);

            MediationRecord mr = new MediationRecord(json);
            mr.sendMediationRecord();
        } catch (JSONException jpe) {
            logger.error("Unable to send mediation record: "+jpe.getMessage());
        }
    }


    /**
     * Validate scopes
     *
     * @param requestedScopes
     * @param defaultScopes
     * @param allowedScopes
     * @param request
     * @return
     * @throws InvalidScopeException
     * @throws ServerException
     */
    private Set<String> validateScopes(Set<String> requestedScopes, Set<String> defaultScopes, Set<String> allowedScopes, OAuth2Request request) throws InvalidScopeException {
        Set<String> scopes;
        if (requestedScopes == null || requestedScopes.isEmpty()) {
            scopes = defaultScopes;
        } else {
            scopes = new HashSet<>(allowedScopes);
            scopes.retainAll(requestedScopes);

            for (String allowedScope : allowedScopes) {
                scopes.addAll(filter(requestedScopes, allowedScope));
            }

            if (requestedScopes.size() > scopes.size()) {
                Set<String> invalidScopes = new HashSet<>(requestedScopes);
                invalidScopes.removeAll(allowedScopes);

                throw InvalidScopeException.create("Unknown/invalid scope(s): " + invalidScopes.toString(), request);
            }
        }

        if (scopes == null || scopes.isEmpty()) {
            throw InvalidScopeException.create("No scope requested and no default scope configured", request);
        }

        return scopes;
    }


    /**
     * Returns a list of dynamically matched scopes against an allowedScope
     *
     * @param requestedScopes
     * @param allowedScope
     * @return
     */
    private Set<String> filter(Set<String> requestedScopes, String allowedScope) {
        Pattern pattern = Pattern.compile(allowedScope);
        return requestedScopes.stream().filter(pattern.asPredicate()).collect(Collectors.toSet());
    }


    /**
     *
     * @param e
     * @return
     */
    private InvalidRequestException unwrapInvalidRequestException(ScriptException e) {
        Throwable exception = e;
        while (exception.getCause() != null) {
            if (exception.getCause() instanceof InvalidRequestException) {
                return (InvalidRequestException) exception.getCause();
            } else {
                exception = exception.getCause();
            }
        }
        return null;
    }


    /**
     *
     * @param providedClaims
     * @return
     */
    private Map<String, Object> providedClaimsToLegacyFormat(List<Claim> providedClaims) {
        Map<String, Object> claims = new HashMap<>();
        for (Claim providedClaim : providedClaims) {
            if (providedClaim.getValues().isEmpty()) {
                claims.put(providedClaim.getName(), null);
            } else {
                List<String> valueObject = providedClaim.getValues();
                if (valueObject.size() > 1) {
                    claims.put(providedClaim.getName(), providedClaim.getValues());
                }else {
                    claims.put(providedClaim.getName(), providedClaim.getValues().iterator().next());
                }
            }
        }

        return claims;
    }


    /**
     *
     * @param requestedClaims
     * @return
     */
    private Map<String, Set<String>> requestedClaimsToLegacyFormat(List<Claim> requestedClaims) {
        Map<String, Set<String>> claims = new HashMap<>();
        for (Claim requestedClaim : requestedClaims) {
            claims.put(requestedClaim.getName(), new HashSet<>(requestedClaim.getValues()));
        }
        return claims;
    }


    /**
     *
     * @param clientRegistration
     * @param token
     * @param response
     * @param providerSettings
     */
    private void addSubToResponseIfOpenIdConnect(ClientRegistration clientRegistration, AccessToken token, List<Claim> response, OAuth2ProviderSettings providerSettings) {
        if (clientRegistration instanceof OpenIdConnectClientRegistration) {
            final String subId = ((OpenIdConnectClientRegistration) clientRegistration).getSubValue(token.getResourceOwnerId(), providerSettings);
            response.add(new Claim(OAuth2Constants.JWTTokenParams.SUB, subId));
        }
    }


    /**
     *
     * @param clientRegistration
     * @return
     */
    private boolean isAgentRequest(ClientRegistration clientRegistration) {
        return clientRegistration instanceof AgentClientRegistration;
    }


    /**
     *
     * @param userInfoClaims
     * @param clientRegistration
     * @param realm
     * @param ssoToken
     * @return
     * @throws ServerException
     */
    private UserInfoClaims addRestrictedSSOTokenToUserInfoClaims(UserInfoClaims userInfoClaims, ClientRegistration clientRegistration, String realm, SSOToken ssoToken) throws ServerException {
        String restrictedTokenId = getRestrictedTokenId(clientRegistration, realm, ssoToken);
        String sessionUid = getSessionUid(ssoToken);
        final JsonValue values = json(object(field(FORGEROCK_CLAIMS, object(
                field(OAuth2Constants.JWTTokenParams.SSO_TOKEN, restrictedTokenId),
                field(OAuth2Constants.JWTTokenParams.SESSION_UID, sessionUid),
                fieldIfNotNull(OAuth2Constants.JWTTokenParams.TRANSACTION_ID,
                        userInfoClaims.getValues().get(OAuth2Constants.JWTTokenParams.TRANSACTION_ID))
        ))));
        return new UserInfoClaims(values.asMap(), userInfoClaims.getCompositeScopes());
    }


    /**
     *
     * @param scopes
     * @return
     */
    private Set<String> getScriptFriendlyScopes(Set<String> scopes) {
        return scopes == null ? new HashSet<>() : new HashSet<>(scopes);
    }


    /**
     *
     * @param claimLocales
     * @return
     */
    private List<String> getScriptFriendlyClaimLocales(List<String> claimLocales) {
        return claimLocales == null ? new ArrayList<>() : new ArrayList<>(claimLocales);
    }


    /**
     *
     * @param ssoToken
     * @return
     * @throws ServerException
     */
    private String getSessionUid(SSOToken ssoToken) throws ServerException {
        try {
            return ssoToken.getProperty(Constants.AM_CTX_ID);
        } catch (SSOException e) {
            logger.warning("Failed to get {}", OAuth2Constants.JWTTokenParams.SESSION_UID, e);
            throw new ServerException("Failed to get " + OAuth2Constants.JWTTokenParams.SESSION_UID);
        }
    }


    /**
     *
     * @param clientRegistration
     * @param realm
     * @param ssoToken
     * @return
     * @throws ServerException
     */
    private String getRestrictedTokenId(ClientRegistration clientRegistration, String realm, SSOToken ssoToken) throws ServerException {
        if (!SystemProperties.getAsBoolean(Constants.IS_ENABLE_UNIQUE_COOKIE)) {
            return ssoToken.getTokenID().toString();
        }

        try {
            TokenRestriction tokenRes = agentValidator.resolve(
                    clientRegistration.getClientId(),
                    realm,
                    AccessController.doPrivileged(AdminTokenAction.getInstance()));

            return sessionService.getRestrictedTokenId(ssoToken.getTokenID().toString(), tokenRes);
        } catch (SSOException | IdRepoException | SMSException | SessionException e) {
            logger.warning("Failed to get restricted session token", e);
            throw new ServerException("Failed to get restricted session token");
        }
    }


    /**
     *
     * @param providerSettings
     * @param request
     * @param token
     * @return
     */
    private List<Claim> gatherRequestedClaims(OAuth2ProviderSettings providerSettings, OAuth2Request request, AccessToken token) {
        if (token != null) {
            String claimsJson = token.getClaims();
            if (request.getRequest().getResourceRef().getLastSegment().equals(OAuth2Constants.UserinfoEndpoint.USERINFO)) {
                return gatherRequestedClaims(providerSettings, claimsJson, OAuth2Constants.UserinfoEndpoint.USERINFO);
            } else {
                return gatherRequestedClaims(providerSettings, claimsJson, OAuth2Constants.JWTTokenParams.ID_TOKEN);
            }
        } else {
            String json = request.getParameter(OAuth2Constants.Custom.CLAIMS);
            return gatherRequestedClaims(providerSettings, json, OAuth2Constants.JWTTokenParams.ID_TOKEN);
        }
    }


    /**
     * Generates a map for the claims specifically requested as per Section 5.5 of the spec.
     * Ends up mapping requested claims against a set of their optional values (empty if
     * claim is requested but no suggested/required values given).
     */
    private List<Claim> gatherRequestedClaims(OAuth2ProviderSettings providerSettings, String claimsJson, String objectName) {
        try {
            if (providerSettings.getClaimsParameterSupported() && claimsJson != null) {
                try {
                    final Claims claims = Claims.parse(claimsJson);

                    switch (objectName) {
                        case OAuth2Constants.JWTTokenParams.ID_TOKEN:
                            return new ArrayList<>(claims.getIdTokenClaims().values());
                        case OAuth2Constants.UserinfoEndpoint.USERINFO:
                            return new ArrayList<>(claims.getUserInfoClaims().values());
                        default:
                            throw new IllegalArgumentException("Invalid claim type");
                    }
                } catch (JSONException e) {
                    //ignorable
                }
            }
        } catch (ServerException e) {
            logger.message("Requested Claims Supported not set.");
        }

        return Collections.emptyList();
    }


    /**
     * Gather requested nested claims
     *
     * @param providerSettings An instance of the {@code OAuth2ProviderSettings}
     * @param request An instance of the {@code OAuth2Request}
     * @param accessToken - AccessToken object
     * @return List<Claim> of requested nested claims
     */
    private List<Claim> gatherRequestedNestedClaims(OAuth2ProviderSettings providerSettings, OAuth2Request request, AccessToken accessToken, String claimSubElement) {
        if (accessToken != null) {
            String claimsJson = accessToken.getClaims();
            return gatherRequestedNestedClaimsFromSub(providerSettings, claimsJson, getRequestInfoType(request), claimSubElement);
        } else {
            String json = request.getParameter(OAuth2Constants.Custom.CLAIMS);
            return gatherRequestedClaims(providerSettings, json, OAuth2Constants.JWTTokenParams.ID_TOKEN);
        }
    }


    /**
     * Returns a List<Claim> with requested nested claims
     *
     * @param providerSettings An instance of the {@code OAuth2ProviderSettings}
     * @param claimsJson - claims string in JSON format
     * @param objectName - name of the object
     * @return - List<Claim> of requested nested claims
     */
    private List<Claim> gatherRequestedNestedClaimsFromSub(OAuth2ProviderSettings providerSettings, String claimsJson, String objectName, String claimSubElement) {
        List<Claim> result = new ArrayList<>();

        try {
            if (providerSettings.getClaimsParameterSupported() && claimsJson != null) {
                try {
                    final Claims claims = Claims.parse(claimsJson);
                    JSONObject subclaims = new JSONObject(claimsJson);

                    switch (objectName) {
                        case OAuth2Constants.JWTTokenParams.ID_TOKEN:
                            for (Claim claim: claims.getIdTokenClaims().values()) {
                                List<Claim> claimsForClaim = getNestedClaimsForClaim(claim.getName(), subclaims, objectName, claimSubElement);
                                if (claimsForClaim != null && claimsForClaim.size() > 0) {
                                    result.addAll(claimsForClaim);
                                }
                            }
                            return result;
                        case OAuth2Constants.UserinfoEndpoint.USERINFO:
                            for (Claim claim: claims.getUserInfoClaims().values()) {
                                List<Claim> claimsForClaim = getNestedClaimsForClaim(claim.getName(), subclaims, objectName, claimSubElement);
                                if (claimsForClaim != null && claimsForClaim.size() > 0) {
                                    result.addAll(claimsForClaim);
                                }
                            }
                            return result;
                        default:
                            throw new IllegalArgumentException("Invalid claim type");
                    }
                } catch (JSONException e) {
                    //ignorable
                }
            }
        } catch (ServerException e) {
            logger.message("Requested Claims Supported not set.");
        }

        return Collections.emptyList();
    }


    /**
     * Return request type as a string (can only be 'userinfo' or 'id_token')
     *
     * @param request OAuth2Request instance
     * @return String indicating what sort of request is being handled
     */
    private String getRequestInfoType(OAuth2Request request) {
        if (request.getRequest().getResourceRef().getLastSegment().equals(OAuth2Constants.UserinfoEndpoint.USERINFO)) {
            return OAuth2Constants.UserinfoEndpoint.USERINFO;
        } else {
            return OAuth2Constants.JWTTokenParams.ID_TOKEN;
        }
    }


    /**
     *
     * @param claimName
     * @param claimsJson
     * @param objectName
     * @return
     */
    private List<Claim> getNestedClaimsForClaim(String claimName, JSONObject claimsJson, String objectName, String key) {
        try {
            JSONObject objectClaimsObject = new JSONObject();
            objectClaimsObject.put(objectName, claimsJson.getJSONObject(objectName).getJSONObject(claimName).getJSONObject(key));
            final Claims nestedClaims = Claims.parse(objectClaimsObject.toString());

            return new ArrayList<>(nestedClaims.getAllClaims().values());
        } catch (JSONException e) {
            // ignore
        }
        return null;
    }


    /**
     * Attempts to get the user's session, which can either be set on the OAuth2Request explicitly
     * or found as a cookie on the http request.
     *
     * @param request The OAuth2Request.
     * @return The user's SSOToken or {@code null} if no session was found.
     */
    private SSOToken getUsersSession(OAuth2Request request) {
        String sessionId = request.getSession();
        if (sessionId == null) {
            final HttpServletRequest req = ServletUtils.getRequest(request.<Request>getRequest());
            if (req.getCookies() != null) {
                final String cookieName = openAMSettings.getSSOCookieName();
                for (final Cookie cookie : req.getCookies()) {
                    if (cookie.getName().equals(cookieName)) {
                        sessionId = cookie.getValue();
                    }
                }
            }
        }
        SSOToken ssoToken = null;
        if (sessionId != null) {
            try {
                ssoToken = SSOTokenManager.getInstance().createSSOToken(sessionId);
            } catch (SSOException e) {
                logger.message("SessionID is not valid");
            }
        }
        return ssoToken;
    }


    /**
     *
     * @param realm
     * @return
     * @throws ServerException
     */
    private ScriptObject getOIDCClaimsExtensionScript(String realm) throws ServerException {

        OpenAMSettingsImpl settings = new OpenAMSettingsImpl(OAuth2Constants.OAuth2ProviderService.NAME, OAuth2Constants.OAuth2ProviderService.VERSION);
        try {
            String scriptId = settings.getStringSetting(realm, OAuth2Constants.OAuth2ProviderService.OIDC_CLAIMS_EXTENSION_SCRIPT);
            if (EMPTY_SCRIPT_SELECTION.equals(scriptId)) {
                return new ScriptObject("oidc-claims-script", "", SupportedScriptingLanguage.JAVASCRIPT);
            }
            ScriptConfiguration config = getScriptConfiguration(realm, scriptId);
            return new ScriptObject(config.getName(), config.getScript(), config.getLanguage());
        } catch (org.forgerock.openam.scripting.ScriptException | SSOException | SMSException e) {
            logger.message("Error running OIDC claims script", e);
            throw new ServerException("Error running OIDC claims script: " + e.getMessage());
        }
    }


    /**
     *
     * @param realm
     * @param scriptId
     * @return
     * @throws org.forgerock.openam.scripting.ScriptException
     */
    private ScriptConfiguration getScriptConfiguration(String realm, String scriptId) throws org.forgerock.openam.scripting.ScriptException {
        return scriptingServiceFactory.create(realm).get(scriptId);
    }


    /**
     *
     * @param username
     * @param realm
     * @param request
     * @return
     * @throws NotFoundException
     */
    private String getUpdatedAt(String username, String realm, OAuth2Request request) throws NotFoundException {
        try {
            final OAuth2ProviderSettings providerSettings = providerSettingsFactory.get(request);
            String modifyTimestampAttributeName;
            String createdTimestampAttributeName;
            try {
                modifyTimestampAttributeName = providerSettings.getModifiedTimestampAttributeName();
                createdTimestampAttributeName = providerSettings.getCreatedTimestampAttributeName();
            } catch (ServerException e) {
                logger.error("Unable to read last modified attribute from datastore", e);
                return DEFAULT_TIMESTAMP;
            }

            if (modifyTimestampAttributeName == null && createdTimestampAttributeName == null) {
                return null;
            }

            final AMHashMap timestamps = getTimestamps(username, realm, modifyTimestampAttributeName,
                    createdTimestampAttributeName);
            final String modifyTimestamp = CollectionHelper.getMapAttr(timestamps, modifyTimestampAttributeName);

            if (modifyTimestamp != null) {
                synchronized (TIMESTAMP_DATE_FORMAT) {
                    return Long.toString(TIMESTAMP_DATE_FORMAT.parse(modifyTimestamp).getTime() / 1000);
                }
            } else {
                final String createTimestamp = CollectionHelper.getMapAttr(timestamps, createdTimestampAttributeName);

                if (createTimestamp != null) {
                    synchronized (TIMESTAMP_DATE_FORMAT) {
                        return Long.toString(TIMESTAMP_DATE_FORMAT.parse(createTimestamp).getTime() / 1000);
                    }
                } else {
                    return DEFAULT_TIMESTAMP;
                }
            }
        } catch (IdRepoException e) {
            if (logger.errorEnabled()) {
                logger.error("ScopeValidatorImpl" +
                                ".getUpdatedAt: " +
                                "error searching Identities with username : " +
                                username, e
                );
            }
        } catch (SSOException | ParseException e) {
            logger.warning("Error getting updatedAt attribute", e);
        }

        return null;
    }


    /**
     *
     * @param username
     * @param realm
     * @param modifyTimestamp
     * @param createTimestamp
     * @return
     * @throws IdRepoException
     * @throws SSOException
     */
    private AMHashMap getTimestamps(String username, String realm, String modifyTimestamp, String createTimestamp) throws IdRepoException, SSOException {
        final SSOToken token = AccessController.doPrivileged(AdminTokenAction.getInstance());
        final AMIdentityRepository amIdRepo = new AMIdentityRepository(token, realm);
        final IdSearchControl searchConfig = new IdSearchControl();

        searchConfig.setReturnAttributes(new HashSet<>(Arrays.asList(modifyTimestamp, createTimestamp)));
        searchConfig.setMaxResults(0);
        final IdSearchResults searchResults = amIdRepo.searchIdentities(IdType.USER, username, searchConfig);

        final Iterator searchResultsItr = searchResults.getResultAttributes().values().iterator();

        if (searchResultsItr.hasNext()) {
            return (AMHashMap) searchResultsItr.next();
        } else {
            logger.warning("Error retrieving timestamps from datastore");
            throw new IdRepoException();
        }
    }
}
