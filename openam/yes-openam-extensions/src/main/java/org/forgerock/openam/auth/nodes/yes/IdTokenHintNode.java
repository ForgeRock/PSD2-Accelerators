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

import com.google.inject.assistedinject.Assisted;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.oauth2.core.OAuth2Jwt;
import org.forgerock.oauth2.core.exceptions.InvalidClientException;
import org.forgerock.oauth2.core.exceptions.NotFoundException;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.ExternalRequestContext;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openidconnect.OpenIdConnectClientRegistration;
import org.forgerock.openidconnect.OpenIdConnectClientRegistrationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import javax.security.auth.callback.NameCallback;
import java.util.Optional;
import java.util.ResourceBundle;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USERNAME;

/**
 * This authentication node turns a 'sub' claim into a valid session when the submitted id_token_hint value is valid.
 *
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class, configClass = IdTokenHintNode.Config.class)
public class IdTokenHintNode extends AbstractDecisionNode {
    private final Logger logger = LoggerFactory.getLogger(IdTokenHintNode.class);
    private static final String BUNDLE = "org/forgerock/openam/auth/nodes/yes/IdTokenHintNode";
    private final Config config;
    private final Realm realm;
    private final OpenIdConnectClientRegistrationStore clientRegistrationStore;

    /**
     * Configuration for the node.
     */
    public interface Config {
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
     * @param clientRegistrationStore OpenIdConnectClientRegistrationStore object with client references
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public IdTokenHintNode(@Assisted Config config,
                           @Assisted Realm realm,
                           OpenIdConnectClientRegistrationStore clientRegistrationStore) throws NodeProcessException {
        this.config = config;
        this.realm = realm;
        this.clientRegistrationStore = clientRegistrationStore;
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
        if (config.debugEnabled()) {
            dumpRequest(context.request);
            dumpSharedState(context.sharedState);
            dumpTransientState(context.transientState);
        }

        Optional<NameCallback> nameCallback = context.getCallback(NameCallback.class);
        String idTokenInput;
        if (nameCallback.isPresent() && nameCallback.get().getName() != null) {
            idTokenInput = nameCallback.get().getName();
            if (config.debugEnabled()) {
                logger.debug("found idTokenInput field: " + idTokenInput);
            }
        }else{
            return this.collectIdTokenHint(context);
        }

        JsonValue sharedState = context.sharedState;
        String username = this.getUsernameFromIdToken(idTokenInput);

        if (username != null || !username.isEmpty()) {
            return goTo(true).replaceSharedState(sharedState.copy().put(USERNAME, username)).build();
        }

        throw new NodeProcessException("unable to get subject from id_token");
    }


    /**
     * Sends a NameCallback response back to the user
     *
     * @param context
     * @return
     */
    private Action collectIdTokenHint(TreeContext context) {
        ResourceBundle bundle = context.request.locales.getBundleInPreferredLocale(BUNDLE, getClass().getClassLoader());
        return send(new NameCallback(bundle.getString("callback.id_token_hint"))).build();
    }


    /**
     *
     * @param idToken
     * @return
     */
    private String getUsernameFromIdToken(String idToken) throws NodeProcessException {
        OAuth2Jwt jwt = this.getOAuth2Jwt(idToken);

        if (this.validateIdToken(jwt)) {
            return jwt.getSubject();
        }
        return null;
    }


    /**
     *
     * @param jwt
     * @return
     */
    private OAuth2Jwt getOAuth2Jwt(String jwt) {
        return OAuth2Jwt.create(jwt);
    }


    /**
     *
     * @param idToken
     * @return
     */
    private boolean validateIdToken(OAuth2Jwt idToken) throws NodeProcessException {
        boolean isValid = false;
        try {
            final OpenIdConnectClientRegistration clientRegistration = clientRegistrationStore.get(idToken);

            if (clientRegistration != null && clientRegistration.verifyIdTokenSignedByUsWithConfiguredAlg(idToken)) {
                logger.error("idToken validated");
                isValid = true;
            }else{
                logger.error("idToken is not valid");
                throw new NodeProcessException("JWT is not valid");
            }
        } catch (InvalidJwtException e) {
            throw new NodeProcessException("id_token is not a valid JWT");
        } catch (ClassCastException e) {
            throw new NodeProcessException("invalid id_token_hint. Encrypted id_tokens are not supported.");
        } catch (NotFoundException e) {
            throw new NodeProcessException("client not found");
        } catch (InvalidClientException e) {
            throw new NodeProcessException("invalid client");
        }

        return isValid;
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
}