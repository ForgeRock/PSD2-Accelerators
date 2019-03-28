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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonRawValue;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.sun.identity.shared.debug.Debug;
import org.forgerock.openam.oauth2.yes.claims.VerifiedPersonData;
import org.forgerock.openidconnect.Claim;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

public class VerifiedPersonDataPlugin implements ClaimMapperPlugin {
    private Map<String, List<Claim>> requestedClaims;
    private Map<String, Object> claimResponse;
    private ClaimMapperConfiguration configuration;
    private VerifiedPersonData verifiedPersonData;
    private final Debug logger = Debug.getInstance("VerifiedPersonDataPlugin");
    private ObjectMapper mapper = new ObjectMapper().setSerializationInclusion(JsonInclude.Include.NON_NULL);
    private String username;


    /**
     * {@inheritDoc}
     */
    public VerifiedPersonDataPlugin(ClaimMapperConfiguration configuration, Map<String, List<Claim>> requestedClaims, String username) {
        this.requestedClaims = requestedClaims;
        this.configuration = configuration;
        this.username = username;
    }


    /**
     * {@inheritDoc}
     */
    @JsonRawValue
    public Map<String, List<Claim>> getRequestedClaims() {
        return requestedClaims;
    }


    /**
     * {@inheritDoc}
     */
    public void setRequestedClaims(Map<String, List<Claim>> requestedClaimsAndScopes) {
        this.requestedClaims = requestedClaimsAndScopes;
    }


    /**
     * {@inheritDoc}
     */
    public Map<String, Object> getClaimResponse() {
        return claimResponse;
    }


    /**
     * {@inheritDoc}
     */
    public void setClaimResponse(Map<String, Object> claimResponse) {
        this.claimResponse = claimResponse;
    }


    /**
     * {@inheritDoc}
     */
    public VerifiedPersonData getVerifiedPersonData() {
        if (this.verifiedPersonData == null) {
            this.setVerifiedPersonData(this.getRemoteVerifiedPersonData());
        }
        return verifiedPersonData;
    }


    /**
     * {@inheritDoc}
     */
    public void setVerifiedPersonData(VerifiedPersonData verifiedPersonData) {
        this.verifiedPersonData = verifiedPersonData;
    }


    /**
     * {@inheritDoc}
     */
    public String getUsername() {
        return this.username;
    }


    /**
     * {@inheritDoc}
     */
    public void setUsername(String username) {
        this.username = username;
    }


    /**
     * {@inheritDoc}
     */
    public ClaimMapperConfiguration getConfiguration() {
        return configuration;
    }


    /**
     * {@inheritDoc}
     */
    public void setConfiguration(ClaimMapperConfiguration configuration) {
        this.configuration = configuration;
    }


    /**
     * Returns an instance of an HTTP client, for communicating with the remote VPD service
     *
     * @return
     */
    private HttpURLConnection getHttpClient() {
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(this.getConfiguration().getRemoteServiceURI()).openConnection();

            httpURLConnection.setRequestMethod(this.getConfiguration().getMethod());
            httpURLConnection.setReadTimeout(this.getConfiguration().getReadTimeout() * 1000);
            httpURLConnection.setConnectTimeout(this.getConfiguration().getConnectTimeout() * 1000);
            httpURLConnection.setInstanceFollowRedirects(false);

            return this.injectHeaders(httpURLConnection);
        } catch (MalformedURLException ue) {
            logger.error("Invalid configuration: URL "+this.getConfiguration().getRemoteServiceURI()+" is not a valid URL");
            logger.message("URISyntaxException details: ",ue);
        } catch (IOException ioe) {
            logger.error("Caught IOException ",ioe);
        }
        return null;
    }


    /**
     * Returns an instance of an HTTP client with injected headers
     *
     * @param httpURLConnection
     * @return
     */
    private HttpURLConnection injectHeaders(HttpURLConnection httpURLConnection) {
        try {
            for (String header : this.getConfiguration().getInjectedHeaders().keySet()) {
                httpURLConnection.setRequestProperty(header, this.getConfiguration().getInjectedHeaders().get(header));
            }
        } catch (NullPointerException npe) {
            logger.error("Unable to inject headers into the VPD request, no headers found");
        }
        return httpURLConnection;
    }


    /**
     * Execute the HTTP call and return the response
     *
     * @param httpURLConnection
     * @return
     */
    private Object getResponse(HttpURLConnection httpURLConnection) {
        try {
            // setup the body first
            httpURLConnection.setDoOutput(true);
            OutputStreamWriter wr = new OutputStreamWriter(httpURLConnection.getOutputStream());

            // this should contain the actual claim names, they're not there.
            wr.write(mapper.writeValueAsString(this.getRequestedClaims()));
            wr.flush();

            int response = httpURLConnection.getResponseCode();

            StringBuilder vpdBuffer = new StringBuilder();
            String line;
            try {
                BufferedReader rd = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
                while ((line = rd.readLine()) != null) {
                    vpdBuffer.append(line);
                }
            } catch (IOException e) {
                logger.error(e.getMessage() + ", token invalid");
                return null;
            }

            return vpdBuffer.toString();
        } catch (ConnectException ce) {
            logger.error("Unable to reach service at URI "+httpURLConnection.getURL().toExternalForm()+": "+ce.getCause().getLocalizedMessage());
        } catch (IOException ioe) {
            logger.error("caught exception ",ioe);
        }
        return null;
    }


    /**
     * Returns the VerifiedPersonData object returned from the remote VPD service
     *
     * @return
     */
    private VerifiedPersonData getRemoteVerifiedPersonData() {
        HttpURLConnection connection = this.getHttpClient();
        Object response = this.getResponse(connection);
        logger.message("Got response from remote service: "+response);

        // TODO: implement logic for when the data is not available
        VerifiedPersonData verifiedPersonData = new VerifiedPersonData();


        if (response != null) {
            try {
                verifiedPersonData = mapper.readValue((String) response, VerifiedPersonData.class);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }else{
            logger.error("Unable to setup verified_person_data object, no response received from remote service");
        }
        return verifiedPersonData;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public String toString() {
        return "VerifiedPersonDataPlugin{" +
                "requestedClaims=" + requestedClaims +
                ", claimResponse=" + claimResponse +
                ", configuration=" + configuration +
                ", verifiedPersonData=" + verifiedPersonData +
                '}';
    }
}
