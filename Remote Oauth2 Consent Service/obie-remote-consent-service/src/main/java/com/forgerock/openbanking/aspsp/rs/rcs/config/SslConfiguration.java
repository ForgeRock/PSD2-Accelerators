/***************************************************************************
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
 ***************************************************************************/
package com.forgerock.openbanking.aspsp.rs.rcs.config;

import org.apache.http.client.HttpClient;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.forgerock.openbanking.aspsp.rs.rcs.exceptions.SslConfigurationFailure;

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

//@Configuration
public class SslConfiguration {

    private static final String JAVA_KEYSTORE = "PKCS12";
    
    @Autowired
    ApplicationProperties applicationProperties;
   

//    @Bean
    public RestTemplate restTemplate() throws Exception {
        return createRestTemplate(false);
    }

//    @Bean(name="restTemplateForRS")
    public RestTemplate restTemplateForRS() throws Exception {
        return createRestTemplate(true);
    }

    public RestTemplate createRestTemplate(boolean useLocalTruststore) throws Exception {
        try {
            SSLContextBuilder sslContextBuilder = new SSLContextBuilder()
                    .loadKeyMaterial(
                            getStore(applicationProperties.getKeyStore().getURL(), applicationProperties.getKeyStorePassword().toCharArray()),
                            applicationProperties.getKeyPassword().toCharArray(),
                            (aliases, socket) -> applicationProperties.getKeyAlias()
                    );

            SSLContext sslContext = sslContextBuilder.build();
            SSLConnectionSocketFactory socketFactory;
            socketFactory = new SSLConnectionSocketFactory(sslContext);
            HttpClient httpClient = HttpClients.custom().setSSLSocketFactory(socketFactory).build();
            HttpComponentsClientHttpRequestFactory factory = new HttpComponentsClientHttpRequestFactory(httpClient);
            return new RestTemplate(factory);
        } catch (Exception e) {
            throw new SslConfigurationFailure(e);
        }
    }

    protected KeyStore getStore(final URL url, final char[] password) throws
            KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        final KeyStore store = KeyStore.getInstance(JAVA_KEYSTORE);
        InputStream inputStream = url.openStream();
        try {
            store.load(inputStream, password);
        } finally {
            inputStream.close();
        }

        return store;
    }
}
