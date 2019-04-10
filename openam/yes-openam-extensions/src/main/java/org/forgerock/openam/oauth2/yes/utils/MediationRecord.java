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
package org.forgerock.openam.oauth2.yes.utils;

import com.sun.identity.shared.debug.Debug;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

public class MediationRecord {
    private final String mediationEndpoint = "http://nc.booleans.local:8787/rest/mediation/record";
    private final String httpMethod = "POST";
    private final Integer timeout = 5;
    private HttpURLConnection httpClient;
    private final Debug logger = Debug.getInstance("MediationRecordLogger");
    private final JSONObject body;

    public MediationRecord(JSONObject body) {
        this.httpClient = this.getHttpClient();
        this.body = body;
    }

    private HttpURLConnection getHttpClient() {
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(this.mediationEndpoint).openConnection();

            httpURLConnection.setRequestMethod(this.httpMethod);
            httpURLConnection.setReadTimeout(this.timeout * 1000);
            httpURLConnection.setConnectTimeout(this.timeout * 1000);
            httpURLConnection.setInstanceFollowRedirects(false);

            return this.injectHeaders(httpURLConnection);
        } catch (MalformedURLException ue) {
            logger.error("Invalid configuration: URL "+this.mediationEndpoint+" is not a valid URL");
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
            httpURLConnection.setRequestProperty("Content-Type", "application/json");

        } catch (NullPointerException npe) {
            logger.error("Unable to inject headers into the VPD request, no headers found");
        }
        return httpURLConnection;
    }


    /**
     * Execute the HTTP call and return the response
     *
     * @return
     */
    private String getResponse() {
        try {
            // setup the body first
            this.httpClient.setDoOutput(true);
            OutputStreamWriter wr = new OutputStreamWriter(this.httpClient.getOutputStream());

            // this should contain the actual claim names, they're not there.
            wr.write(this.body.toString());
            wr.flush();

            int response = this.httpClient.getResponseCode();

            StringBuilder vpdBuffer = new StringBuilder();
            String line;
            try {
                BufferedReader rd = new BufferedReader(new InputStreamReader(this.httpClient.getInputStream()));
                while ((line = rd.readLine()) != null) {
                    vpdBuffer.append(line);
                }
            } catch (IOException e) {
                return null;
            }

            return vpdBuffer.toString();
        } catch (Exception ioe) {
            logger.error("caught exception "+ioe.getMessage());
        }
        return null;
    }

    /**
     *
     */
    public void sendMediationRecord() {
        this.getResponse();
    }
}
