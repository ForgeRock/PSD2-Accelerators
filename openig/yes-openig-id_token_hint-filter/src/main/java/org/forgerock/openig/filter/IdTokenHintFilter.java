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
import org.forgerock.http.header.CookieHeader;
import org.forgerock.http.header.LocationHeader;
import org.forgerock.http.header.SetCookieHeader;
import org.forgerock.http.protocol.Cookie;
import org.forgerock.http.protocol.Form;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.JsonValue;
import org.forgerock.json.jose.common.JwtReconstruction;
import org.forgerock.json.jose.exceptions.InvalidJwtException;
import org.forgerock.json.jose.jwk.JWK;
import org.forgerock.json.jose.jwk.JWKSet;
import org.forgerock.json.jose.jwk.JWKSetParser;
import org.forgerock.json.jose.jwk.KeyUse;
import org.forgerock.json.jose.jws.SignedJwt;
import org.forgerock.json.jose.jws.SigningManager;
import org.forgerock.json.jose.jws.handlers.SigningHandler;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.SimpleHTTPClient;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.time.Duration;
import org.forgerock.util.time.TimeService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import static org.forgerock.http.protocol.Response.newResponsePromise;
import static org.forgerock.json.JsonValueFunctions.duration;
import static org.forgerock.json.JsonValueFunctions.uri;
import static org.forgerock.openig.heap.Keys.CLIENT_HANDLER_HEAP_KEY;
import static org.forgerock.openig.util.JsonValues.optionalHeapObject;
import static org.forgerock.util.Reject.checkNotNull;


/**
 * Class to validate the id_token_hint parameter
 *
 */
public class IdTokenHintFilter implements Filter {
    private static final Logger logger = LoggerFactory.getLogger(IdTokenHintFilter.class);
    private static long CLOCK_SKEW_MILLIS = 0L;
    private static long MAX_LIFETIME_LIMIT = 0L;
    private static final String ERROR = "login_required";
    private static final String ERROR_DESCRIPTION = "Authentication required";
    private final TimeService timeService = TimeService.SYSTEM;
    private final Handler executionHandler;
    private final URI authTreeEndpoint;
    private final String amSessionCookie;
    private final URI sessionValidationEndpoint;
    private final String cookieDomain;
    private final Boolean updateCookieResponse;
    private final Boolean cookieHttpOnly;
    private final Boolean cookieSecure;
    private final Duration clockSkew;
    private final Duration maxLifetimeLimit;
    private URI jwksEndpoint;
    private Boolean validateIdToken;


    /**
     * Construct a new IdTokenHintFilter
     *
     * @param executionHandler Handler object to use for communication with AM
     * @param authTreeEndpoint URI pointing to the authentication tree that contains the IdTokenHint node
     * @param validateIdToken Boolean indicating whether the id_token should be validated here (next to validation inside AM)
     * @param jwksEndpoint URI pointing to the jwk_uri for signature validation
     */
    public IdTokenHintFilter(final Handler executionHandler,
                             final Boolean validateIdToken,
                             final URI jwksEndpoint,
                             final URI authTreeEndpoint,
                             final URI sessionValidationEndpoint,
                             final Duration clockSkew,
                             final Duration maxLifetimeLimit,
                             final String amSessionCookie,
                             final Boolean updateCookieResponse,
                             final Boolean cookieHttpOnly,
                             final Boolean cookieSecure,
                             final String cookieDomain) {
        this.executionHandler = checkNotNull(executionHandler);
        this.validateIdToken = validateIdToken;
        if (this.validateIdToken) {
            this.jwksEndpoint = checkNotNull(jwksEndpoint, "validateIdToken is set to true, but no jwksEndpoint provided");
        }
        this.authTreeEndpoint = checkNotNull(authTreeEndpoint);
        this.amSessionCookie = amSessionCookie;
        this.sessionValidationEndpoint = sessionValidationEndpoint;
        this.clockSkew = clockSkew;
        this.maxLifetimeLimit = maxLifetimeLimit;
        this.updateCookieResponse = updateCookieResponse;
        this.cookieHttpOnly = cookieHttpOnly;
        this.cookieSecure = cookieSecure;
        this.cookieDomain = cookieDomain;

        CLOCK_SKEW_MILLIS = this.clockSkew.convertTo(TimeUnit.MILLISECONDS).getValue();
        MAX_LIFETIME_LIMIT = this.maxLifetimeLimit.convertTo(TimeUnit.MILLISECONDS).getValue();
    }


    /**
     * Returns a promise holding the response from AM when id_token_hint contains a valid value.
     *
     * @param context Context object
     * @param request Request object
     * @param handler Handler object
     * @return Promise<Response, NeverThrowsException> response object
     */
    @Override
    public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler handler) {
        List<String> id_token_hints = request.getForm().get("id_token_hint");
        String redirectUri = request.getForm().getFirst("redirect_uri");
        logger.debug("redirect_uri from request: "+redirectUri);
        String id_token_hint = null;

        try {
            String newSession = null;
            if (id_token_hints != null && id_token_hints.size() != 0) {
                if (id_token_hints.size() > 1) {
                    logger.error("id_token_hint has multiple values: [" + id_token_hints + "] - cannot determine which one to use.");
                } else {
                    id_token_hint = id_token_hints.get(0);
                }
            }

            if (id_token_hint != null) {
                String existingSession = this.getAmSessionCookieValue(request);
                if (validateIdToken) {
                    try {
                        SignedJwt jwt = new JwtReconstruction().reconstructJwt(id_token_hint, SignedJwt.class);
                        JWK jwkSet = this.getJwk(jwt);
                        SigningHandler signingHandler = new SigningManager().newVerificationHandler(jwkSet);
                        
                        if (this.isValid(signingHandler, jwt)) {
                            logger.debug("id_token is valid!");
                        } else {
                            logger.error("id_token is invalid!");
                            return redirectWithError(this.getRedirectUri(redirectUri, ERROR, ERROR_DESCRIPTION));
                        }
                    } catch (InvalidJwtException ije) {
                        logger.error("Invalid JWT in id_token_hint");
                        return redirectWithError(this.getRedirectUri(redirectUri, ERROR, ERROR_DESCRIPTION));
                    }
                }

                // perform a request to the custom tree, where the id_token can be exchanged for a session
                // this session is then injected into the original request (as cookie as well as csrf)
                // modify the response to include the set-cookie header as returned from AM
                if (this.sessionValidationEndpoint != null) {
                    if (existingSession != null && this.validateSessionCookie(context, existingSession)) {
                        logger.trace("session is still valid, reusing it.");
                    }else{
                        // session is not there, or not valid. Lets get a new one.
                        newSession = this.getSessionFromIdTokenHint(context, id_token_hint);
                    }
                }
            }else{
                logger.trace("No id_token_hint found inside POST body, continuing without modifications");
            }

            if (newSession != null) {
                this.modifyRequestCookies(request, newSession);
                this.modifyCsrf(request, newSession);
            }
            Promise<Response, NeverThrowsException> response = handler.handle(context, request);
            if (this.updateCookieResponse && newSession != null) {
                this.modifyResponseCookies(response.get(), newSession);
            }
            return response;
        } catch (InterruptedException e) {
            logger.error("current thread was interrupted: "+e.getMessage());
            logger.debug("Associated stacktrace: ",e);
        } catch (ExecutionException e) {
            logger.error("unable to complete the id_token_hint flow: "+e.getMessage());
            logger.debug("Associated stacktrace: ",e);
        }
        return null;
    }


    /**
     * Replaces the csrf value with the value of the new session
     *
     * @param request Request object to modify
     * @param sessionId String with sessionId to use as csrf
     */
    private void modifyCsrf(Request request, String sessionId) {
        Form form = request.getForm();
        form.putSingle("csrf", sessionId);
        request.setEntity(form.toFormString());
    }


    /**
     * Replace/add cookie with the sessionId on the request towards AM
     *
     * @param request Request object to modify
     * @param sessionId String with sessionId to store inside the request object
     */
    private void modifyRequestCookies(Request request, String sessionId) {
        List<Cookie> cookies = new ArrayList<>();
        Cookie newCookie = new Cookie();
        newCookie.setName(this.amSessionCookie);
        newCookie.setValue(sessionId);
        cookies.add(newCookie);

        if (request.getCookies() == null || request.getCookies().isEmpty()) {
            request.addHeaders(new CookieHeader(cookies));
        }else{
            request.getCookies().put(this.amSessionCookie, cookies);
        }
    }


    /**
     * Adds a new Set-Cookie to the response
     *
     * @param response Reponse object to modify
     * @param sessionId String with sessionId to store inside the response object
     */
    private void modifyResponseCookies(Response response, String sessionId) {
        List<Cookie> cookies = new ArrayList<>();
        Cookie newCookie = new Cookie();
        newCookie.setName(this.amSessionCookie);
        newCookie.setValue(sessionId);
        newCookie.setDomain(this.cookieDomain);
        newCookie.setHttpOnly(this.cookieHttpOnly);
        newCookie.setSecure(this.cookieSecure);
        cookies.add(newCookie);

        if (response.getHeaders().get("Set-Cookie") == null) {
            response.getHeaders().add(new SetCookieHeader(cookies));
        }else{
            response.getHeaders().put(new SetCookieHeader(cookies));
        }
    }


    /**
     * Returns the session cookie value from the request
     *
     * @param request Request object
     * @return String containing the session cookie value
     */
    private String getAmSessionCookieValue(Request request) {
        try {
            Cookie existingCookie = request.getCookies().get(this.amSessionCookie).get(0);
            return existingCookie.getValue();
        } catch (NullPointerException npe) {
            logger.error("no existing cookie with name "+this.amSessionCookie+" found");
        }
        return null;
    }


    /**
     * Returns the JWK object that matches the algorithm and usage, with a fallback to the keyId if not found.
     *
     * @param jwt
     * @return
     */
    private JWK getJwk(SignedJwt jwt) {
        try {
            JWKSet jwkSet = new JWKSetParser(new SimpleHTTPClient()).jwkSet(this.jwksEndpoint.toURL());

            JWK jwk = jwkSet.findJwk(jwt.getHeader().getAlgorithm(), KeyUse.SIG);
            if (jwk == null) {
                logger.error("No JWK found that matches algorithm "+jwt.getHeader().getAlgorithm().getAlgorithm()+" and keyuse "+KeyUse.SIG.value()+", attempting lookup via kid "+jwt.getHeader().getKeyId());
                jwk = jwkSet.findJwk(jwt.getHeader().getKeyId());
            }

            logger.trace("found jwkSet: "+jwk.toJsonString());
            return jwk;
        } catch (Exception e) {
            logger.error("caught exception while getting jwks response ", e);
            e.printStackTrace(System.err);
        }
        return null;
    }


    /**
     * Returns the session from the IdTokenHint node within AM
     *
     * @param context Context object
     * @param idTokenHint String containing the id_token_hint
     * @return
     */
    private String getSessionFromIdTokenHint(Context context, String idTokenHint) {
        Request callbackRequest = this.getCallbackRequest();
        Promise<Response, NeverThrowsException> callbackResponse = this.getHttpResponsePromise(context, callbackRequest);

        try {
            logger.trace("received callbackResponse: "+callbackResponse.get().getEntity().toString());

            JsonValue filledCallback = this.fillCallbackValue(new JsonValue(callbackResponse.get().getEntity().getJson()), idTokenHint);
            logger.trace("composed filledCallback: "+filledCallback.toString());
            Request scRequest = this.submitCallbackRequest(filledCallback);
            Promise<Response, NeverThrowsException> scResponse = this.getHttpResponsePromise(context, scRequest);

            logger.trace("received submitCallbackResponse: "+scResponse.get().getEntity().toString());

            if (scResponse.get().getStatus().getCode() == Status.OK.getCode()) {
                return this.getSessionId(new JsonValue(scResponse.get().getEntity().getJson()));
            }else{
                logger.error("submitting callback failed with status "+scResponse.get().getStatus().getCode()+" and body "+scResponse.get().getEntity().toString());
            }
        } catch (InterruptedException e) {
            logger.error("current thread was interrupted: "+e.getMessage());
            logger.debug("Associated stacktrace: ",e);
        } catch (ExecutionException | IOException e) {
            logger.error("unable to get the sessionId: "+e.getMessage());
            logger.debug("Associated stacktrace: ",e);
        }
        return null;
    }


    /**
     * Validates a session against AM
     *
     * @param context Context object
     * @param existingSession String containing existing sessionId
     * @return
     */
    private Boolean validateSessionCookie(Context context, String existingSession) {
        Request request = this.getSessionValidationRequest(existingSession);
        Promise<Response, NeverThrowsException> sessionValidationResponse = this.getHttpResponsePromise(context, request);

        try {
            JsonValue sessionValidationJson = new JsonValue(sessionValidationResponse.get().getEntity().getJson());
            if (sessionValidationJson.get("valid").asBoolean()) {
                return true;
            }
        } catch (InterruptedException e) {
            logger.error("Current thread was interrupted: "+e.getMessage());
            logger.debug("Associated stacktrace: ",e);
        } catch (ExecutionException | IOException e) {
            logger.error("unable to validate the sessionId: "+e.getMessage());
            logger.debug("Associated stacktrace: ",e);
        }
        return false;
    }


    /**
     * Builds a Request object with the correct parameters to obtain a callback from a specific service
     *
     * @return Request object with all the necessary settings
     */
    private Request getCallbackRequest() {
        Request request = new Request();
        request.setMethod("POST");
        request.getHeaders().add("Content-Type", "application/json");
        request.getHeaders().add("Accept-API-Version", "protocol=1.0,resource=1.0");
        request.setUri(this.authTreeEndpoint);
        return request;
    }


    /**
     * Builds a Request object with the correct parameters to submit a callback towards the node in AM
     *
     * @param filledCallback
     * @return
     */
    private Request submitCallbackRequest(JsonValue filledCallback) {
        Request request = new Request();
        request.setMethod("POST");
        request.getHeaders().add("Content-Type", "application/json");
        request.getHeaders().add("Accept-API-Version", "protocol=1.0,resource=1.0");
        request.setUri(this.authTreeEndpoint);
        request.setEntity(filledCallback);

        return request;
    }


    /**
     * Builds a Request object with the correct parameters to validate a session against AM
     *
     * @param sessionId
     * @return
     */
    private Request getSessionValidationRequest(String sessionId) {
        Request request = new Request();
        request.setMethod("POST");
        request.getHeaders().add("Content-Type", "application/json");
        request.getHeaders().add("Accept-API-Version", "resource=3.1, protocol=1.0");
        request.getHeaders().put(this.amSessionCookie, sessionId);
        request.setUri(this.sessionValidationEndpoint);

        return request;
    }


    /**
     * Returns the session identifier as returned from AM in an authentication call
     *
     * @param value JsonValue containing the response from an authentication
     * @return String containing the sessionId
     */
    private String getSessionId(JsonValue value) {
        return value.get("tokenId").asString();
    }


    /**
     * Returns filled JsonValue with the value set to the id_token_hint
     *
     * @param callbackResponse JsonValue object containing the callback response from AM
     * @param idTokenHint String containing the id_token_hint
     * @return JsonValue object containing the filled callback value
     */
    private JsonValue fillCallbackValue(JsonValue callbackResponse, String idTokenHint) {
        JsonValue filledCallback = callbackResponse.copy();
        try {
            filledCallback.get("callbacks").get(0).get("input").get(0).put("value", idTokenHint);
        } catch (Exception e) {
            logger.error("Unable to fill the callback with id_token: "+e.getMessage());
            logger.debug("Associated stacktrace: ",e);
        }
        return filledCallback;
    }


    /**
     * Execute an HTTP request and return the response as Promise
     *
     * @param context Context object
     * @param request Request Object
     * @return Promise<Response, NeverThrowsException> containing the HTTP response
     */
    private Promise<Response, NeverThrowsException> getHttpResponsePromise(final Context context, final Request request) {
        logger.debug("contacting service at "+request.getUri().toASCIIString());
        return executionHandler.handle(context, request);
    }


    /**
     * Creates the redirect URL for custom error messages
     *
     * @param uri String containing the redirectUri
     * @param error String containing the error
     * @param errorDescription String containing the error description
     * @return String containing the full redirectUri with error query parameters added
     */
    private String getRedirectUri(String uri, String error, String errorDescription) {
        try {
            URI orgRedirectUri = new URI(uri);
            String appendQueryString = "error="+checkNotNull(error)+"&error_description="+errorDescription;
            String queryParams = orgRedirectUri.getQuery();
            if (queryParams == null) {
                queryParams = appendQueryString;
            } else {
                queryParams += "&"+appendQueryString;
            }

            return new URI(orgRedirectUri.getScheme(),
                    orgRedirectUri.getAuthority(),
                    orgRedirectUri.getPath(),
                    queryParams,
                    orgRedirectUri.getFragment()
            ).toString();

            // return newUri.toString();
        } catch (URISyntaxException use) {
            logger.error("Invalid URL: "+use.getMessage());
            logger.debug("Associated stacktrace: ",use);
        }
        return null;
    }


    /**
     * Redirect to an endpoint
     *
     * @param redirectUri String containing the URL to redirect to
     * @return Promise<Response, NeverThrowsException> containing the response
     */
    private Promise<Response, NeverThrowsException> redirectWithError(String redirectUri) {
        Response redirectResponse = new Response(Status.FOUND);
        redirectResponse.getHeaders().put(LocationHeader.NAME, redirectUri);
        return newResponsePromise(redirectResponse);
    }


    /**
     * Verifies that the JWT is valid by:
     * <ul>
     * <li>verifying the signature</li>
     * <li>ensuring the JWT contains the 'iss', 'sub', 'aud' and 'exp' claims</li>
     * <li>ensuring the JWT expiry is not unreasonably far in the future</li>
     * <li>ensuring the JWT has not expired</li>
     * <li>ensuring the JWT is not being used before its 'not before time'</li>
     * <li>ensuring the JWT issued at time is not unreasonably far in the past</li>
     * </ul>
     *
     * @param signingHandler The {@link SigningHandler} instance to verify the JWT signature with.
     * @return {@code true} if the JWT meets all the expectations.
     */
    public boolean isValid(SigningHandler signingHandler, SignedJwt jwt) {
        Boolean isSignatureValid = jwt.verify(signingHandler);
        logger.debug("isSignatureValid yields "+isSignatureValid);
        return isSignatureValid && isContentValid(jwt);
    }


    /**
     * Verifies that the JWT is valid by:
     * <ul>
     * <li>ensuring the JWT contains the 'iss', 'sub', 'aud' and 'exp' claims</li>
     * <li>ensuring the JWT expiry is not unreasonably far in the future</li>
     * <li>ensuring the JWT has not expired</li>
     * <li>ensuring the JWT is not being used before its 'not before time'</li>
     * <li>ensuring the JWT issued at time is not unreasonably far in the past</li>
     * </ul>
     *
     * @return {@code true} if the JWT meets all the expectations.
     */
    public boolean isContentValid(SignedJwt jwt) {
        return contains(jwt,"iss", "aud", "exp") &&
                !isExpired(jwt) &&
                !isNowBeforeNbf(jwt) &&
                !isIssuedAtUnreasonable(jwt);
    }


    /**
     * Checks if specific claims are in the SignedJwt
     *
     * @param jwt SignedJwt object
     * @param keys list of keys to validate against the SignedJwt
     * @return {@code true} if the claim is part of the SignedJwt
     */
    private boolean contains(SignedJwt jwt, String... keys) {
        for (String key : keys) {
            if (jwt.getClaimsSet().getClaim(key) == null) {
                return false;
            }
        }
        return true;
    }


    /**
     * Checks that the JWT has not expired.
     *
     * @param jwt SignedJwt object
     * @return {@code true} if the JWT has expired.
     */
    public boolean isExpired(SignedJwt jwt) {
        return jwt.getClaimsSet().getExpirationTime() == null
                || jwt.getClaimsSet().getExpirationTime().getTime() <= (timeService.now() - CLOCK_SKEW_MILLIS);
    }


    /**
     * Checks that the 'not before' is earlier than the current time, with taking a clock skew into account
     *
     * @param jwt SignedJwt object
     * @return {@code true} if the SignedJwt 'nbf' claim is later than the current time
     */
    private boolean isNowBeforeNbf(SignedJwt jwt) {
        boolean present = jwt.getClaimsSet().get("nbf").getObject() != null;
        return present && timeService.now() + CLOCK_SKEW_MILLIS < jwt.getClaimsSet().getNotBeforeTime().getTime();
    }


    /**
     * Checks that the Jwt is issued before a specific time
     *
     * @param jwt SignedJwt object
     * @return {@code true} if the SignedJwt was issued earlier than deemed acceptable.
     */
    private boolean isIssuedAtUnreasonable(SignedJwt jwt) {
        boolean present = jwt.getClaimsSet().get("iat").getObject() != null;
        return present && jwt.getClaimsSet().getIssuedAtTime().getTime() < (timeService.now() - MAX_LIFETIME_LIMIT);
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
            URI jwksEndpoint              = config.get("jwksEndpoint").as(evaluatedWithHeapProperties()).as(uri());
            URI authenticationEndpoint    = config.get("authenticationEndpoint").as(evaluatedWithHeapProperties()).as(uri());
            String authenticationTreeName = config.get("authenticationTreeName").as(evaluatedWithHeapProperties()).asString();
            URI sessionValidationEndpoint = config.get("sessionValidationEndpoint").as(evaluatedWithHeapProperties()).as(uri());
            Boolean validateIdToken       = config.get("validateIdToken").defaultTo(true).asBoolean();
            Handler executionHandler      = config.get("executionHandler").defaultTo(CLIENT_HANDLER_HEAP_KEY).as(optionalHeapObject(heap, Handler.class));
            String amSessionCookie        = config.get("amSessionCookie").as(evaluatedWithHeapProperties()).asString();
            Duration clockSkewDuration    = config.get("clockSkew").as(evaluatedWithHeapProperties()).defaultTo("3 minutes").as(duration());
            Duration maxLifetimeDuration  = config.get("maxLifetimeLimit").as(evaluatedWithHeapProperties()).defaultTo("1 day").as(duration());
            JsonValue cookieSettings      = config.get("updateCookieConfig").as(evaluatedWithHeapProperties());
            Boolean updateCookieResponse  = cookieSettings.get("updateSetCookie").defaultTo(true).asBoolean();
            Boolean cookieHttpOnly        = cookieSettings.get("cookieHttpOnly").defaultTo(true).asBoolean();
            Boolean cookieSecure          = cookieSettings.get("cookieSecure").defaultTo(true).asBoolean();
            String cookieDomain           = cookieSettings.get("cookieDomain").asString();

            String appendQueryString = "authIndexType=service&authIndexValue="+authenticationTreeName;
            String queryParams = authenticationEndpoint.getQuery();
            if (queryParams == null) {
                queryParams = appendQueryString;
            } else {
                queryParams += "&"+appendQueryString;
            }

            URI authenticationTreeEndpoint = null;
            try {
                authenticationTreeEndpoint = new URI(authenticationEndpoint.getScheme(),
                        authenticationEndpoint.getAuthority(),
                        authenticationEndpoint.getPath(),
                        queryParams,
                        authenticationEndpoint.getFragment()
                );
            } catch (URISyntaxException use) {
                logger.error("Unable to compose the authenticationTreeEndpoint URL: "+use.getMessage());
                logger.debug("Associated stacktrace: ",use);
            }

            return new IdTokenHintFilter(
                    executionHandler,
                    validateIdToken,
                    jwksEndpoint,
                    authenticationTreeEndpoint,
                    sessionValidationEndpoint,
                    clockSkewDuration,
                    maxLifetimeDuration,
                    amSessionCookie,
                    updateCookieResponse,
                    cookieHttpOnly,
                    cookieSecure,
                    cookieDomain
            );
        }
    }
}