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
package org.forgerock.openam.auth.nodes.yes;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.inject.assistedinject.Assisted;
import com.iplanet.dpro.session.SessionException;
import com.iplanet.dpro.session.SessionID;
import com.iplanet.dpro.session.service.SessionService;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.oauth2.OAuth2Constants;
import org.forgerock.openam.oauth2.yes.claims.VerifiedPersonData;
import org.forgerock.openam.oauth2.yes.plugins.PluginWrapper;
import org.forgerock.openam.session.Session;
import org.forgerock.openidconnect.Claim;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.inject.Provider;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import static org.forgerock.openam.oauth2.yes.utils.ScopeToClaimsMapper.getAllRequestedClaims;
import static org.forgerock.openam.oauth2.yes.utils.ScopeToClaimsMapper.getClaimsForScope;

/**
 * A node that retrieves verified person data from a remote service and stores it in the session.
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = VerifiedPersonDataCollectorNode.Config.class)
public class VerifiedPersonDataCollectorNode extends AbstractDecisionNode {
    private final Logger logger = LoggerFactory.getLogger(VerifiedPersonDataCollectorNode.class);
    private final Config config;
    private final Realm realm;
    private final Provider<SessionService> sessionServiceProvider;
    private final ObjectMapper mapper;

    // supported methods for communicating with the remote VPD service
    public enum VpdHttpMethod {
        POST,
        GET,
        PUT;
    }

    // supported methods for authenticating against remote VPD service
    public enum VpdAuthMethod {
        NONE,
        BASIC
    }

    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The class of the plugin that fetches the data from the remote verified person data service
         *
         * @return String
         */
        @Attribute(order = 100)
        default String pluginClass() {
            return "org.forgerock.openam.oauth2.yes.plugins.VerifiedPersonDataPlugin";
        }


        /**
         * Remote URL of the verified person data service
         *
         * @return String
         */
        @Attribute(order = 200)
        default String remoteVPDService() {
            return "http://10.0.2.2:8789/rest/vpd/get_verified_person_data";
        }


        /**
         * HTTP method to use while communicating with the remote verified person data service
         *
         * @return VpdHttpMethod
         */
        @Attribute(order = 300)
        default VpdHttpMethod httpMethod() {
            return VpdHttpMethod.POST;
        }


        /**
         * Connect timeout in seconds for the communication with the remote verified person data service
         *
         * @return Integer
         */
        @Attribute(order = 400)
        default Integer connectTimeout() {
            return 30;
        }


        /**
         * Read timeout in seconds for reading the response from the remote verified person data service
         *
         * @return Integer
         */
        @Attribute(order = 500)
        default Integer readTimeout() {
            return 5;
        }


        /**
         * Authentication method for the remote verified person data service. This depends on the implementation inside
         * the plugin returned by pluginClass().
         *
         * @return VpdAuthMethod
         */
        @Attribute(order = 600)
        default VpdAuthMethod authMethod() {
            return VpdAuthMethod.NONE;
        }

        
        /**
         * Setting additional debugging. When enabled, specific details about the request are being logged.
         * This dumps the shared_state, the transient_state, the request, the callbacks and the session details.
         *
         * WARNING: this should not be enabled for anything other than debugging purposes! The shared_state and the transient_state
         * in particular could hold sensitive information (like passwords, session id's and so on).
         *
         * @return
         */
        @Attribute(order=700)
        default Boolean debugEnabled() {
            return false;
        }
    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm The realm the node is in.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public VerifiedPersonDataCollectorNode(@Assisted Config config, @Assisted Realm realm, Provider<SessionService> sessionServiceProvider) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
        this.sessionServiceProvider = sessionServiceProvider;
        this.mapper = new ObjectMapper();
    }


    /**
     * The main method called by the auth tree implementation
     *
     * @param context TreeContext in which operation is taking place
     * @return Action
     * @throws NodeProcessException
     */
    @Override
    public Action process(TreeContext context) throws NodeProcessException {
        Action.ActionBuilder actionBuilder = goTo(true);

        if (config.debugEnabled()) {
            dumpRequest(context.request);
            dumpSharedState(context.sharedState);
            dumpTransientState(context.transientState);
            dumpCallbacks(context.getAllCallbacks());
            dumpSession(context.request.ssoTokenId);
        }

        String gotoUrl = this.getGotoParam(context.sharedState);

        if (gotoUrl != null) {
            List<String> claimsList = null;
            List<String> scopeList = null;

            try {
                scopeList = this.getRequestedScopes(gotoUrl);
            } catch (NullPointerException npe) {
                logger.warn("No scopes available inside gotoUrl "+gotoUrl);
            }

            try {
                claimsList = this.getRequestedClaims(gotoUrl);
            } catch (NullPointerException npe) {
                logger.warn("No claims available inside gotoUrl "+gotoUrl);
            }

            VerifiedPersonData vpd;
            try {
                if (scopeList != null && scopeList.size() > 0) {
                    for (String scopename : scopeList) {
                        List<Claim> claimsForScope = getClaimsForScope(scopename);
                        if (null != claimsForScope && claimsForScope.size() > 1) {
                            vpd = this.getVerifiedPersonData(scopeList, claimsList, this.getUsername(context.sharedState));
                            actionBuilder.putSessionProperty(scopename, mapper.writeValueAsString(vpd));
                        } else {
                            logger.warn("No claims retrieved for scope " + scopename);
                        }
                    }
                }
            } catch (JsonProcessingException je) {
                logger.error("Unable to parse verified person data for scopes: "+je.getMessage());
            }

            try {
                if (claimsList != null && claimsList.size() > 0) {
                    for (String claimName : claimsList) {
                        vpd = this.getVerifiedPersonData(scopeList, claimsList, this.getUsername(context.sharedState));
                        actionBuilder.putSessionProperty(claimName, mapper.writeValueAsString(vpd));
                    }
                }
            } catch (JsonProcessingException jpe) {
                logger.error("Unable to parse verified person data for claims: "+jpe.getMessage());
            }
        }else{
            logger.warn("No goto URL found inside shared state, cannot set session info");
        }

        return actionBuilder.build();
    }


    /**
     * Parse and return the request parameters
     *
     * @param url
     * @return
     */
    private List<NameValuePair> getRequestParameterMap(String url) {
        List<NameValuePair> requestParameters = new ArrayList<>();
        try {
            requestParameters = URLEncodedUtils.parse(new URI(url), StandardCharsets.UTF_8.toString());
        } catch (URISyntaxException use) {
            logger.error("Unable to get requestParameters from URL "+url+": ",use);
        }
        return requestParameters;
    }


    /**
     * Extract requested scopes from a URL
     *
     * @param url
     * @return
     */
    private List<String> getRequestedScopes(String url) {
        List<NameValuePair> paramsList = this.getRequestParameterMap(url);
        List<String> scopeMap = new ArrayList<>();

        for (final NameValuePair param : paramsList) {
            if (param.getName().equalsIgnoreCase(OAuth2Constants.Params.SCOPE)) {
                scopeMap = Arrays.asList(param.getValue().split("\\s+"));
            }
        }
        return scopeMap;
    }


    /**
     * Extract requested claims from a URL
     *
     * @param url
     * @return
     */
    private List<String> getRequestedClaims(String url) {
        List<NameValuePair> paramsList = this.getRequestParameterMap(url);
        List<String> claimsMap = new ArrayList<>();

        for (final NameValuePair param : paramsList) {
            if (param.getName().equalsIgnoreCase(OAuth2Constants.JwtClaimConstants.CLAIMS)) {
                try {
                    JsonFactory factory = mapper.getFactory();
                    JsonParser jsonParser = factory.createParser(param.getValue());
                    JsonNode node = mapper.readTree(jsonParser);

                    Iterator<String> it = node.fieldNames();
                    while (it.hasNext()) {
                        JsonNode key = node.get(it.next());
                        Iterator<String> keyIt = key.fieldNames();
                        while (keyIt.hasNext()) {
                            String claimName = keyIt.next();
                            if (!claimsMap.contains(claimName)) {
                                claimsMap.add(claimName);
                            }
                        }
                    }
                } catch (JsonProcessingException jpe) {
                    logger.error("Unable to process the claims as parameter: "+jpe.getMessage());
                } catch (IOException ioe) {
                    logger.error("Caught IOException while parsing the claims as parameter: "+ioe.getMessage());
                }
            }
        }
        return claimsMap;
    }


    /**
     * Gets the goto parameter from the shared state object
     *
     * @param state
     * @return
     */
    private String getGotoParam(JsonValue state) {
        return state.get("userGotoParam").asString();
    }


    /**
     *
     * @param sharedState
     * @return
     */
    private String getUsername(JsonValue sharedState) {
        return sharedState.get("username").asString();
    }


    /**
     *
     * @param scopes
     * @param claims
     * @param username
     * @return
     */
    private VerifiedPersonData getVerifiedPersonData(List<String> scopes, List<String> claims, String username) {
        Map<String, List<Claim>> requestedClaimsAndScopes = getAllRequestedClaims(scopes, claims);

        Map<String, String> injectedHeaders = new HashMap<>();
        injectedHeaders.put("Content-Type", "application/json");

        PluginWrapper pluginWrapper = new PluginWrapper(config.remoteVPDService(), config.httpMethod().name(), injectedHeaders, config.pluginClass(), config.connectTimeout(), config.readTimeout());
        return pluginWrapper.getVerifiedPersonData(requestedClaimsAndScopes, username);
    }


    /**
     *
     * @param requestContext
     */
    private void dumpRequest(ExternalRequestContext requestContext) {
        // dump request parameters
        for (String entry : requestContext.parameters.keySet()) {
            logger.debug("Param name: \""+entry+"\" with value \""+requestContext.parameters.get(entry)+"\"");
        }

        // dump request headers
        for (String header : requestContext.headers.keySet()) {
            logger.debug("Header name \""+header+"\" with value \""+requestContext.headers.get(header)+"\"");
        }

        logger.debug("Client IP property value: "+requestContext.clientIp);
        logger.debug("Hostname property value from request: "+requestContext.hostName);
        logger.debug("ServerURL property value from request: "+requestContext.serverUrl);
        logger.debug("SSOToken property value from request: "+requestContext.ssoTokenId);

        // dump cookies
        for (String cookieName : requestContext.cookies.keySet()) {
            logger.debug("Incoming cookie with name \""+cookieName+"\" and value \""+requestContext.cookies.get(cookieName)+"\"");
        }
    }


    /**
     *
     * @param sharedState
     */
    private void dumpSharedState(JsonValue sharedState) {
        logger.debug("shared state contents: "+sharedState.toString());
    }


    /**
     *
     * @param transientState
     */
    private void dumpTransientState(JsonValue transientState) {
        logger.debug("transient state contents: "+transientState.toString());
    }


    /**
     *
     * @param callbacks
     */
    private void dumpCallbacks(List callbacks) {
        for (Object item : callbacks) {
            logger.debug("found callback: "+item.toString());
        }
    }


    /**
     *
     * @param tokenId
     */
    private void dumpSession(String tokenId) {
        if (tokenId == null || tokenId.length() == 0) {
            logger.error("Unable to dump any session parameters as no session currently exists");
        }else{
            logger.error("got sessionID "+tokenId);
            try {
                Session oldSession = this.sessionServiceProvider.get().getSession(new SessionID(tokenId));
                Map<String, String> sessionProperties = oldSession.getProperties();
                for (String sessionKey : sessionProperties.keySet()) {
                    logger.error("found session key "+sessionKey+" with value "+sessionProperties.get(sessionKey));
                }
            } catch (SessionException se) {
                logger.error("Caught session exception: ",se);
            }
        }
    }
}