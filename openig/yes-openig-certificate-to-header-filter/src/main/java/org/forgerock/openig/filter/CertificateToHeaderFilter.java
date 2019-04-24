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
package org.forgerock.openig.filter;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.header.GenericHeader;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Class to inject the client certificate into a header towards AM
 *
 */
public class CertificateToHeaderFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(CertificateToHeaderFilter.class);
    private final String targetHeader;


    public CertificateToHeaderFilter(String targetHeader) {
        this.targetHeader = targetHeader;
    }


    /**
     * Returns a promise holding the response from AM
     *
     * @param context Context object
     * @param request Request object
     * @param handler Handler object
     * @return Promise<Response, NeverThrowsException> response object
     */
    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler handler) {
        AttributesContext attrContext = context.getContext("attributes").asContext(AttributesContext.class);
        Map<String, Object> attributes = new LinkedHashMap(attrContext.getAttributes());
        try {
            HttpServletRequest httpServletRequest = (HttpServletRequest) attributes.get("javax.servlet.http.HttpServletRequest");
            X509Certificate certs[] = (X509Certificate[]) httpServletRequest.getAttribute("javax.servlet.request.X509Certificate");

            if (certs.length > 0) {
                byte[] derCert = certs[0].getEncoded();
                String pemEncodedCertificate = new String(Base64.getEncoder().encode(derCert));
                logger.trace("PEM encoded certificate: " + pemEncodedCertificate);

                if (request.getHeaders().get(targetHeader) == null) {
                    request.getHeaders().add(new GenericHeader(targetHeader, pemEncodedCertificate));
                } else {
                    request.getHeaders().put(new GenericHeader(targetHeader, pemEncodedCertificate));
                }
            } else {
                logger.warn("Client certificate list is empty, not injecting any headers");
            }
        } catch (CertificateEncodingException cee) {
            logger.error("Client certificate is there but cannot be encoded: "+cee.getMessage());

        } catch (NullPointerException npe) {
            logger.error("Unable to retrieve client certificate from request, not injecting any headers");
        }

        Promise<Response, NeverThrowsException> response = handler.handle(context, request);
        return response;
    }


    /**
     * Create and initialize the filter, based on the configuration.
     * The filter object is stored in the heap.
     */
    public static class Heaplet extends GenericHeaplet {

        /**
         * Create the filter object in the heap, setting the necessary fields for the filter, based on the configuration.
         *
         * @return                  The filter object.
         * @throws HeapException    Failed to create the object.
         */
        @Override
        public Object create() throws HeapException {
            String targetHeader = config.get("targetHeader").as(evaluatedWithHeapProperties()).asString();

            return new CertificateToHeaderFilter(targetHeader);
        }
    }
}