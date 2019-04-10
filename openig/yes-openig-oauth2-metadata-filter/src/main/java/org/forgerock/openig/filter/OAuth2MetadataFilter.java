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
import org.forgerock.http.MutableUri;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.regex.Pattern;

import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.http.protocol.Responses.newInternalServerError;


/**
 * Class to rewrite .well-known/openid-configuration to a .well-known/oauth-authorization-server response
 *
 */
public class OAuth2MetadataFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(OAuth2MetadataFilter.class);
    private String rewriteFrom;
    private String rewriteTo;
    private Boolean rewriteResponseBody;
    private Boolean excludeSymmetric;
    private Map<String, Object> rewriteFields;


    /**
     * Replaces a pattern inside the request path for reverse proxying
     *
     */
    private String rewritePath(String pattern, String fromPath, String toPath) {
        Pattern p = Pattern.compile("^"+pattern, Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
        String newString = p.matcher(fromPath).replaceAll(toPath);
        return newString;
    }


    /**
     * Rewrite the .well-known/openid-configuration to a .well-known/oauth-authorization-server response.
     *
     * This removes several fields, and also reuses the certificate information from the userinfo_* parameters for introspection_* parameters.
     * See: https://datatracker.ietf.org/doc/rfc8414/?include_text=1
     *
     * @param responseBody Object containing the original response from AM
     * @return JsonValue with rewritten metadata
     */
    private JsonValue rewriteMetadata(Object responseBody) {
        JsonValue metadata = new JsonValue(responseBody);

        /* sets the introspection_signing_alg_values_supported to the same value as the id_token_signing_alg_values_supported from the response */
        if (this.rewriteFields == null || this.rewriteFields.size() == 0) {
            logger.warn("No configuration provided for 'rewriteFields', assuming default behaviour");
            metadata.add("introspection_signing_alg_values_supported", removeSymmetric(metadata.get("userinfo_signing_alg_values_supported").asList()));
        }else{
            for (String sourceFieldname : this.rewriteFields.keySet()) {
                metadata.add((String)this.rewriteFields.get(sourceFieldname), removeSymmetric(metadata.get(sourceFieldname).asList()));
            }
        }

        /* remove some other fields; please add your own ones */
        metadata.remove("claims_parameter_supported");
        metadata.remove("userinfo_endpoint");
        metadata.remove("userinfo_encryption_enc_values_supported");
        metadata.remove("userinfo_encryption_alg_values_supported");
        metadata.remove("userinfo_signing_alg_values_supported");
        metadata.remove("code_challenge_methods_supported");
        metadata.remove("id_token_signing_alg_values_supported");
        metadata.remove("id_token_encryption_alg_values_supported");
        metadata.remove("id_token_encryption_enc_values_supported");

        return metadata;
    }


    /**
     * Removes symmetric signing algorithms
     *
     * @param input
     * @return
     */
    private List<Object> removeSymmetric(List<Object> input) {
        if (!excludeSymmetric) {
            return input;
        }
        List<Object> newList = new ArrayList<>();
        for (Object object : input) {
            if (!((String)object).startsWith("HS")) {
                newList.add(object);
            }
        }
        return newList;
    }


    /**
     * Rewrites the request from .well-known/openid-configuration to .well-known/oauth-authorization-server, modifies the response and returns it.
     *
     * @param context
     * @param request
     * @param handler
     * @return
     */
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler handler) {
        MutableUri newUri = request.getUri();

        try {
            String rewrittenPath = rewritePath(this.rewriteFrom, newUri.getPath(), this.rewriteTo);
            newUri.setPath(rewrittenPath);
            request.setUri(newUri.asURI());
        } catch (URISyntaxException use) {
            logger.error("Caught URISyntaxException while rewriting the URL from "+this.rewriteFrom+" to "+this.rewriteTo+": "+use.getMessage());
            logger.debug("Associated stacktrace: ",use);
            return internalServerError();
        } catch (NullPointerException npe) {
            logger.error("Caught NullPointerException while rewriting the URL from "+this.rewriteFrom+" to "+this.rewriteTo+": "+npe.getMessage());
            logger.debug("Associated stacktrace: ",npe);
            return internalServerError();
        }

        // collect the response for further processing
        Promise<Response, NeverThrowsException> response = handler.handle(context, request);

        try {
            if (rewriteResponseBody) {
                if (!response.get().getEntity().isDecodedContentEmpty() || !response.get().getEntity().isRawContentEmpty()) {
                    response.get().setEntity(this.rewriteMetadata(response.get().getEntity().getJson()));
                }
            }
        } catch (ExecutionException ee) {
            logger.error("Could not get the response body from the response: "+ee.getMessage());
            logger.debug("Associated stacktrace: ",ee);
            return internalServerError();
        } catch (IOException | InterruptedException ie) {
            logger.error("Could not rewrite the metadata in the response: "+ie.getMessage());
            logger.debug("Associated stacktrace: ",ie);
        }
        return response;
    }


    /**
     * Returns an internal server error when an error has occurred.
     *
     * @return
     */
    private Promise<Response, NeverThrowsException> internalServerError() {
        return newResponsePromise(newInternalServerError(new InternalServerErrorException("internal server error")));
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
            OAuth2MetadataFilter filter = new OAuth2MetadataFilter();
            filter.rewriteFrom = config.get("rewriteFrom").as(evaluatedWithHeapProperties()).required().asString();
            filter.rewriteTo = config.get("rewriteTo").as(evaluatedWithHeapProperties()).required().asString();
            filter.rewriteResponseBody = config.get("rewriteResponseBody").as(evaluatedWithHeapProperties()).required().asBoolean();
            filter.excludeSymmetric = config.get("excludeSymmetricAlgorithms").as(evaluatedWithHeapProperties()).required().asBoolean();
            filter.rewriteFields = config.get("rewriteFields").as(evaluatedWithHeapProperties()).asMap();

            return filter;
        }
    }
}
