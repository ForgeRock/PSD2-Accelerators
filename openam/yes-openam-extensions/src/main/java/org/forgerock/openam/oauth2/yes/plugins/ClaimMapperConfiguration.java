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

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
public class ClaimMapperConfiguration {
    private String remoteServiceURI;
    private Integer connectTimeout = 10;
    private Integer readTimeout = 10;
    private String method = "POST";
    private Map<String,String> injectedHeaders;

    public ClaimMapperConfiguration() {
        // default constructor
    }

    @JsonProperty("remoteServiceURI")
    public String getRemoteServiceURI() {
        return remoteServiceURI;
    }

    @JsonProperty("remoteServiceURI")
    public void setRemoteServiceURI(String remoteServiceURI) {
        this.remoteServiceURI = remoteServiceURI;
    }

    @JsonProperty("connectTimeout")
    public Integer getConnectTimeout() {
        return connectTimeout;
    }

    @JsonProperty("connectTimeout")
    public void setConnectTimeout(Integer connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    @JsonProperty("readTimeout")
    public Integer getReadTimeout() {
        return readTimeout;
    }

    @JsonProperty("readTimeout")
    public void setReadTimeout(Integer readTimeout) {
        this.readTimeout = readTimeout;
    }

    @JsonProperty("method")
    public String getMethod() {
        return method;
    }

    @JsonProperty("method")
    public void setMethod(String method) {
        this.method = method;
    }

    @JsonProperty("injectedHeaders")
    public Map<String, String> getInjectedHeaders() {
        return injectedHeaders;
    }

    @JsonProperty("injectedHeaders")
    public void setInjectedHeaders(Map<String, String> injectedHeaders) {
        this.injectedHeaders = injectedHeaders;
    }

    @Override
    public String toString() {
        return "ClaimMapperConfiguration{" +
                "remoteServiceURI='" + remoteServiceURI + '\'' +
                ", connectTimeout=" + connectTimeout +
                ", readTimeout=" + readTimeout +
                ", method='" + method + '\'' +
                ", injectedHeaders=" + injectedHeaders +
                '}';
    }
}
