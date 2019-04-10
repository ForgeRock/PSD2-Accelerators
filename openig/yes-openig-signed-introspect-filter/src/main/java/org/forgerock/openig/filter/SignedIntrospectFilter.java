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
import org.forgerock.json.jose.builders.JwtClaimsSetBuilder;
import org.forgerock.json.jose.builders.SignedJwtBuilderImpl;
import org.forgerock.json.jose.jwk.KeyUse;
import org.forgerock.json.jose.jws.JwsAlgorithm;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.SupportedEllipticCurve;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.json.jose.jwt.JwtClaimsSet;
import org.forgerock.json.resource.InternalServerErrorException;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.secrets.SecretsService;
import org.forgerock.secrets.NoSuchSecretException;
import org.forgerock.secrets.keys.CryptoKey;
import org.forgerock.secrets.keys.DataDecryptionKey;
import org.forgerock.secrets.keys.SigningKey;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URISyntaxException;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.http.protocol.Responses.newInternalServerError;
import static org.forgerock.openig.heap.Keys.CLIENT_HANDLER_HEAP_KEY;
import static org.forgerock.openig.secrets.SecretsUtils.retrieveCryptoKeyFromSecretId;
import static org.forgerock.openig.secrets.SecretsUtils.retrieveKeyFromSecretId;
import static org.forgerock.openig.util.JsonValues.optionalHeapObject;


/**
 * Class to sign introspection responses
 *
 */
public class SignedIntrospectFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(SignedIntrospectFilter.class);
    private JsonValue signConfig;
    private JsonValue additionalDataConfig;
    private SecretsService secretService;
    private String signAlgorithm;
    private List<String> srcFields;
    private String srcType;
    private Handler dataRetrievalHandler;


    /**
     * Returns a promise holding the SignedJwt as its response body.
     *
     * @param context Context object
     * @param request Request object
     * @param handler Handler object
     * @return Promise<Response, NeverThrowsException> response object
     */
    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler handler) {
        final String requestAccessToken = request.getForm().getFirst("token");
        final String requestHostHeader = request.getHeaders().getFirst("Host");
        final MutableUri requestUri = request.getUri();

        // collect the response for further processing
        Promise<Response, NeverThrowsException> response = handler.handle(context, request);

        if (this.signConfig.isNull()) {
            logger.error("Incorrect configuration - unable to find signature config!");
            return internalServerError();
        }

        JsonValue signSecretId = this.signConfig.get("secretId");

        if (signSecretId.isNotNull()) {
            try {
                final Key key = retrieveKeyFromSecretId(this.secretService, signSecretId, SigningKey.class);
                final SigningHandler signingHandler = new SigningManager().newSigningHandler(key);
                final JwsAlgorithm signAlgorithm = JwsAlgorithm.parseAlgorithm(this.signAlgorithm);
                String kid = this.getKid(signSecretId);

                Map data = (LinkedHashMap) response.get().getEntity().getJson();
                if (this.additionalDataConfig.isNotNull()) {
                    data = this.addAdditionalData(context, requestHostHeader, requestAccessToken, requestUri, data);
                }

                // setup the signed JWT for returning in the response.
                JwtClaimsSet claimsSet = new JwtClaimsSetBuilder().claims(data).build();
                String jws = new SignedJwtBuilderImpl(signingHandler)
                        .headers().kid(kid).alg(signAlgorithm).done()
                        .claims(claimsSet)
                        .build();

                // modify the response
                response.get().setEntity(jws);
                response.get().getHeaders().replace("Content-Type", "application/jwt");
            } catch (NoSuchSecretException e) {
                logger.error("unable to get secret ", e);
                return internalServerError();
            } catch (IllegalArgumentException iae) {
                logger.error("incorrect algorithm configuration: "+iae.getMessage());
                return internalServerError();
            } catch (InterruptedException e) {
                logger.error("current thread was interrupted: "+e.getMessage());
                return internalServerError();
            } catch (ExecutionException e) {
                logger.error("unable to create signedJwt: "+e.getMessage());
                return internalServerError();
            } catch (IOException e) {
                logger.error("unable to create signedJwt: "+e.getMessage());
            }
        }else{
            logger.error("No signSecretId found - cannot sign the response");
        }

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
            SignedIntrospectFilter filter = new SignedIntrospectFilter();
            filter.signConfig = config.get("signature");
            filter.secretService = getSecretService();
            filter.signAlgorithm = filter.signConfig.get("algorithm").as(evaluatedWithHeapProperties()).defaultTo("RS256").asString();
            filter.additionalDataConfig = config.get("additionalData").defaultTo(null);
            filter.srcType = filter.additionalDataConfig.get("sourceType").asString();
            filter.srcFields = filter.additionalDataConfig.get("fields").as(evaluatedWithHeapProperties()).asList(String.class);
            filter.dataRetrievalHandler = config.get("dataHandler").defaultTo(CLIENT_HANDLER_HEAP_KEY).as(optionalHeapObject(heap, Handler.class));

            return filter;
        }
    }


    /**
     * Returns an internal server error when an error has occurred.
     *
     * @return Promise<Response, NeverThrowsException> containing an internal server error Response object
     */
    private Promise<Response, NeverThrowsException> internalServerError() {
        return newResponsePromise(newInternalServerError(new InternalServerErrorException("internal server error")));
    }


    /**
     * Returns a kid in the same format as AM uses.
     *
     * @param signSecretId JsonValue containing the signing secret
     * @return String containing the kid value as composed from the public key
     */
    private String getKid(JsonValue signSecretId) {
        String kid = null;
        try {
            CryptoKey cryptoKey = retrieveCryptoKeyFromSecretId(this.secretService, signSecretId, DataDecryptionKey.class);
            String keyAlias = cryptoKey.getStableId();
            Optional<Certificate> optionalCertificate = cryptoKey.getCertificate();
            X509Certificate x509Certificate;

            if (optionalCertificate.isPresent()) {
                x509Certificate = (X509Certificate) optionalCertificate.get();
                PublicKey publicKey = x509Certificate.getPublicKey();

                if (publicKey instanceof RSAPublicKey) {
                    RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
                    kid = Hash.hash(keyAlias + ":" + KeyUse.SIG + rsaPublicKey.getModulus().toString() + rsaPublicKey.getPublicExponent().toString());
                } else if (publicKey instanceof ECPublicKey) {
                    ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
                    BigInteger x = ecPublicKey.getW().getAffineX();
                    BigInteger y = ecPublicKey.getW().getAffineY();
                    SupportedEllipticCurve c = SupportedEllipticCurve.forKey(ecPublicKey);
                    kid = Hash.hash(keyAlias + ":" + KeyUse.SIG + ":" + c.getStandardName() + ":" + x.toString() + ":" + y.toString());
                } else {
                    logger.error("Cannot return a kidAlias for key " + publicKey);
                }
            }
        } catch (NoSuchSecretException nsse) {
            logger.error("Unable to fetch secret for secretId "+signSecretId+": ",nsse);
        }
        return kid;
    }


    /**
     * Adds additional data to the existing data, based on the configuration. Currently only userinfo responses are used, other types are left as an exercise.
     *
     * @param context context object
     * @param hostHeader String containing the host header
     * @param accessToken String containing the accessToken
     * @param requestUri MutableUri from the original request
     * @param data existing data
     * @return modified Map with data
     */
    private Map addAdditionalData(Context context, String hostHeader, String accessToken, MutableUri requestUri, Map data) {
        if (srcType.equalsIgnoreCase("userinfo")) {

            MutableUri userInfoURI = this.getUserInfoURI(requestUri);
            JsonValue userInfoResponse = this.getUserInfoResponse(context, userInfoURI, hostHeader, accessToken);

            if (userInfoResponse != null) {
                for (String fieldName : this.srcFields) {
                    try {
                        data.put(fieldName, userInfoResponse.get(fieldName));
                    } catch (NullPointerException npe) {
                        logger.debug("No data found for field "+fieldName+" inside userinfo response");
                    }
                }
            }else{
                logger.error("No userinfo response returned, cannot add the data");
            }
        }

        return data;
    }


    /**
     * Executes the request to get info from the userinfo endpoint
     *
     * @param context context object
     * @param request request object containing the custom headers and URI
     * @return Promise containing the Response object
     */
    private Promise<Response, NeverThrowsException> getUserInfoResponsePromise(final Context context, final Request request) {
        return dataRetrievalHandler.handle(context, request);
    }


    /**
     * Returns the JsonValue containing the response body from the userinfo request
     *
     * @param context context object
     * @param userInfoUri MutableUri pointing towards the userinfo endpoint
     * @param hostHeader String containing the host header
     * @param accessToken String containing the accessToken
     * @return JsonValue containing the body
     */
    private JsonValue getUserInfoResponse(Context context, MutableUri userInfoUri, String hostHeader, String accessToken) {
        Request userInfoRequest = new Request().setUri(userInfoUri.asURI());
        userInfoRequest.getHeaders().putIfAbsent("Authorization", "Bearer "+accessToken);
        userInfoRequest.setMethod("GET");
        userInfoRequest.getHeaders().put("Host", hostHeader);

        Promise<Response, NeverThrowsException> userInfoResponsePromise = this.getUserInfoResponsePromise(context, userInfoRequest);

        try {
            Response userInfoResponse = userInfoResponsePromise.get();
            return new JsonValue(userInfoResponse.getEntity().getJson());
        } catch (IOException ioe) {
            logger.error("Caught IOException while getting userinfo data: ",ioe);
        } catch (ExecutionException ee) {
            logger.error("Caught ExecutionException while getting userinfo data: ",ee);
        } catch (InterruptedException ie) {
            logger.error("Caught InterruptedException while getting userinfo data: ",ie);
        }

        return null;
    }


    /**
     * Returns the userinfo URI as a string
     *
     * @param uri original URI to use as a base for composing the userinfo URI
     * @return MutableUri object pointing towards the introspect endpoint
     */
    private MutableUri getUserInfoURI(MutableUri uri) {
        try {
            String url = uri.getScheme()+"://"+uri.getHost()+":"+uri.getPort();
            url += uri.getPath();
            url = url.replaceAll("introspect$", "userinfo");
            return new MutableUri(url);
        } catch (URISyntaxException use) {
            logger.error("Unable to compose userinfo URI: ", use);
        }
        return null;
    }
}
