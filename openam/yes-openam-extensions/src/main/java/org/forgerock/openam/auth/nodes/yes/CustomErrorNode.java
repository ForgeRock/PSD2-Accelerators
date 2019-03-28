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
import com.sun.identity.authentication.spi.RedirectCallback;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SingleOutcomeNode;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.util.List;

import static org.forgerock.openam.auth.node.api.Action.send;
import static org.forgerock.openam.auth.node.api.SharedStateConstants.USER_GOTO_PARAM_KEY;

/**
 * A node that creates a custom error redirect callback
 */
@Node.Metadata(outcomeProvider = SingleOutcomeNode.OutcomeProvider.class, configClass = CustomErrorNode.Config.class)
public class CustomErrorNode extends SingleOutcomeNode {
    private final Logger logger = LoggerFactory.getLogger(CustomErrorNode.class);
    private final Config config;
    private final String REDIRECT_URI = "redirect_uri";
    private final String STATE = "state";
    private final String NONCE = "nonce";


    /**
     * Configuration for the node.
     */
    public interface Config {
        /**
         * The error code to be mapped
         * @return
         */
        @Attribute(order = 100)
        default String errorCode() {
            return "<error>";
        }

        /**
         * The description for the error code
         * @return
         */
        @Attribute(order = 200)
        default String errorDescription() {
            return "<error_description>";
        }

    }


    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @throws NodeProcessException If the configuration was not valid.
     */
    @Inject
    public CustomErrorNode(@Assisted Config config) throws NodeProcessException {
        this.config = config;
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
        logger.debug("goto from shared state={}", context.sharedState.get(USER_GOTO_PARAM_KEY) );
        logger.debug("parameters:{}", context.request.parameters);
        List<String> gotoUrl = context.request.parameters.get("goto");
        if (gotoUrl != null){
            String redirectUri = getParamValue(gotoUrl.get(0),REDIRECT_URI);
            String targetUrl = redirectUri+"?error="+config.errorCode()+"&error_description="+config.errorDescription();
            String state = getParamValue(gotoUrl.get(0),STATE);
            if (state != null)
                targetUrl += "&state=" + state;
            String nonce = getParamValue(gotoUrl.get(0),NONCE);
            if (nonce != null)
                targetUrl += "&nonce=" + nonce;
            RedirectCallback callback = new RedirectCallback(targetUrl, null, "GET");
            callback.setTrackingCookie(true);
            return send(callback).build();
        }
        throw new NodeProcessException("No goto parameter in URL");
    }


    /**
     * Extracts parameter from a URL
     *
     * @param url url to extract parameter from
     * @param param name of the parameter
     * @return String with the parameter value
     */
    private String getParamValue(String url, String param){
        String value=null;
        if (url.contains(param)){
            try {
                int start = url.indexOf(param)+param.length()+1;
                int end = url.indexOf("&", start);
                end = (end == -1 ? url.length() : end);
                value= URLDecoder.decode(url.substring(start, end),"UTF-8");
                logger.debug("param="+value);
            } catch (UnsupportedEncodingException ex) {
                logger.error("Exception when try to decode param {} ",param);
            }
        }
        return value;
    }
}