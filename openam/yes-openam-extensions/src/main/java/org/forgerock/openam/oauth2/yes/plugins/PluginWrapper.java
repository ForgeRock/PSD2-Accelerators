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
package org.forgerock.openam.oauth2.yes.plugins;

import org.forgerock.openam.oauth2.yes.claims.VerifiedPersonData;
import org.forgerock.openidconnect.Claim;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.InvocationTargetException;
import java.util.List;
import java.util.Map;

public class PluginWrapper {
    private final Logger logger = LoggerFactory.getLogger(PluginWrapper.class);
    private final String remoteService;
    private final String httpMethod;
    private final Map<String, String> injectedHeaders;
    private final String pluginClass;
    private final Integer connectTimeout;
    private final Integer readTimeout;


    /**
     *
     * @param remoteService
     * @param httpMethod
     * @param injectedHeaders
     * @param pluginClass
     * @param connectTimeout
     * @param readTimeout
     */
    public PluginWrapper(String remoteService, String httpMethod, Map<String, String> injectedHeaders, String pluginClass, Integer connectTimeout, Integer readTimeout) {
        this.remoteService = remoteService;
        this.httpMethod = httpMethod;
        this.injectedHeaders = injectedHeaders;
        this.pluginClass = pluginClass;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }


    /**
     *
     * @param requestedClaimsAndScopes
     * @param username
     * @return
     */
    public VerifiedPersonData getVerifiedPersonData(Map<String, List<Claim>> requestedClaimsAndScopes, String username) {
        ClaimMapperPlugin claimMapperPlugin = this.getClaimMapperPlugin(requestedClaimsAndScopes, username);

        // this then speaks to a remote service, where the data is retrieved.
        assert claimMapperPlugin != null;
        return claimMapperPlugin.getVerifiedPersonData();
    }


    /**
     * Return a claim mapper plugin instance
     *
     * @param requestedClaimsAndScopes
     * @return
     */
    private ClaimMapperPlugin getClaimMapperPlugin(Map<String, List<Claim>> requestedClaimsAndScopes, String username) {
        ClaimMapperConfiguration claimMapperConfiguration = new ClaimMapperConfiguration();

        claimMapperConfiguration.setConnectTimeout(this.connectTimeout);
        claimMapperConfiguration.setReadTimeout(this.readTimeout);
        claimMapperConfiguration.setRemoteServiceURI(this.remoteService);
        claimMapperConfiguration.setMethod(this.httpMethod);
        claimMapperConfiguration.setInjectedHeaders(this.injectedHeaders);

        try {
            Class claimDataMapper = Class.forName(this.pluginClass);

            Class[] pluginClasses = new Class[3];
            pluginClasses[0] = ClaimMapperConfiguration.class;
            pluginClasses[1] = Map.class;
            pluginClasses[2] = String.class;

            return (ClaimMapperPlugin) claimDataMapper.getDeclaredConstructor(pluginClasses).newInstance(
                    claimMapperConfiguration,
                    requestedClaimsAndScopes,
                    username
            );
        } catch (ClassNotFoundException cnfe) {
            logger.debug("class " + this.pluginClass + " could not be located");
        } catch (NoSuchMethodException nse) {
            logger.error("class exists, but does not have the necessary method.", nse);
        } catch (InstantiationException ie) {
            logger.error("class " + this.pluginClass + " could not be instantiated: ", ie);
        } catch (InvocationTargetException ite) {
            logger.error("invocationTargetException caught: ",ite);
        } catch (IllegalAccessException iae) {
            logger.error("illegalAccessException caught: ",iae);
        }
        return null;
    }
}
