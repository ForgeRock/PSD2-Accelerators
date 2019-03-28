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
package nl.booleans.oidc.yes.rcs.server;

import com.fasterxml.jackson.core.JsonFactory;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWT;
import net.minidev.json.JSONObject;
import nl.booleans.oidc.yes.rcs.api.ConsentHandler;
import nl.booleans.oidc.yes.rcs.api.JwtHandler;
import nl.booleans.oidc.yes.rcs.api.exceptions.DecryptionException;
import nl.booleans.oidc.yes.rcs.api.exceptions.InvalidJwt;
import nl.booleans.oidc.yes.rcs.model.Consent;
import org.owasp.esapi.ESAPI;

import javax.servlet.ServletContext;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.HttpMethod;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static nl.booleans.oidc.yes.rcs.utils.RCSUtils.parseJwt;

@Path("/rcs")
public class RemoteConsentService {

    /**
     * When running embedded these properties can be set through MAVEN_OPTS. I.e:
     *
     *   bash$ MAVEN_OPTS="${MAVEN_OPTS} -Dproperty=value <other options>" mvn jetty:run
     *
     * This should be made configurable, which is left as an exercise to the reader
     */
    private String keyAlias = System.getProperty("keyAlias");
    private String remoteJwksUri = System.getProperty("jwksUri");
    private String keystorePath = System.getProperty("keystorePath");
    private String keyPass = System.getProperty("keyPass");
    private String storePass = System.getProperty("storePass");
    private Boolean shouldEncryptConsentResponse = Boolean.parseBoolean(System.getProperty("encryptResponse"));
    private String localIssuer = System.getProperty("localIssuer");

    private String cookieName = System.getProperty("cookieName");
    private Boolean shouldRetrieveDataFromSession = Boolean.parseBoolean(System.getProperty("useSessionData"));
    private String sessionService = System.getProperty("sessionService");
    private ObjectMapper mapper = new ObjectMapper();


    /**
     * Inject the servlet context
     */
    @Context
    ServletContext context;


    /**
     * Returns the JWKSet in the response based on the keystore parameters provided.
     *
     * @return - Response object containing a JWKSet
     */
    @GET
    @Path("/jwks_uri")
    @Produces(MediaType.APPLICATION_JSON)
    public Response jwksResponse() {
        JwtHandler jwtHandler = new JwtHandler(keystorePath, keyAlias, storePass, keyPass, remoteJwksUri);
        JWKSet jwkSet;
        try {
            jwkSet = jwtHandler.getLocalJWKSet();

            if (jwkSet != null && jwkSet.getKeys().size() > 0) {
                return Response.status(Response.Status.OK).entity(jwkSet.toString()).build();
            }
        } catch (UnsupportedOperationException uoe) {
            System.out.println("Caught UnsupportedOperationException: ["+uoe.getMessage()+"]");
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("{ \"status\": 500, \"error_message\": \""+uoe.getMessage()+"\" }").build();
        }

        return Response.status(Response.Status.OK).entity(new JWKSet().toString()).build();
    }


    /**
     * Serve the consent page based on the "consent_request" parameter. This parameter is parsed as JWT and used for additional processing.
     *
     * @param headers - header object to read the session cookie from, if session retrieval is enabled
     * @param consentRequest - original consent_request query parameter from request
     * @return - Response object containing the response
     */
    @GET
    @Path("/consent")
    @Produces(MediaType.TEXT_HTML)
    public Response getConsentPage(@Context HttpHeaders headers, @QueryParam("consent_request") String consentRequest) {
        Map<String, Cookie> cookies = headers.getCookies();
        Cookie sessionCookie = null;
        if (this.cookieName != null && this.shouldRetrieveDataFromSession) {
            sessionCookie = cookies.get(this.cookieName);
        }

        if (consentRequest != null) {
            ConsentHandler consentHandler = new ConsentHandler(
                    consentRequest,
                    remoteJwksUri,
                    keystorePath,
                    keyAlias,
                    keyPass,
                    storePass,
                    shouldEncryptConsentResponse,
                    localIssuer
            );

            try {
                JWT consentRequestJwt = consentHandler.getConsentRequest();
                if (consentRequestJwt != null) {
                    String username = consentHandler.getUsername(consentRequestJwt);

                    Map<String, Consent> alreadyConsented = consentHandler.getPersistedScopesAndClaims(username);
                    Map<String, Object> claimsMap = (Map<String, Object>)consentRequestJwt.getJWTClaimsSet().getClaims().get("claims");
                    Map<String, Object> scopesMap = (Map<String, Object>)consentRequestJwt.getJWTClaimsSet().getClaims().get("scopes");

                    if (!consentHandler.haveConsentForAllScopes(username, scopesMap) || !consentHandler.haveConsentForAllClaims(username, claimsMap)) {
                        return this.getConsentRequestPage(consentRequestJwt, consentRequest, alreadyConsented, username, sessionCookie);
                    }else{
                        return this.getConsentAlreadyDonePage(consentRequestJwt, consentRequest, alreadyConsented, username);
                    }
                }
            } catch (InvalidJwt invalidJwt) {
                System.err.println("Consent request JWT is invalid: "+invalidJwt.getMessage());
                invalidJwt.printStackTrace();
            } catch (ParseException e) {
                System.err.println("Unable to parse JWT: "+e.getMessage());
                e.printStackTrace();
            } catch (DecryptionException e) {
                System.err.println("Unable to decrypt consent request: "+e.getMessage());
                e.printStackTrace();
            }
        }else{
            return Response.status(Response.Status.BAD_REQUEST).entity("consent_request parameter missing").build();
        }
        return Response.status(Response.Status.BAD_REQUEST).entity("consent_request has expired. Please go back and try again.").build();
    }


    /**
     * Handle the consented scopes/claims, persist them in the DAO and returns a self-submitting form which posts back to the OAuth2 AS with a "consent_response".
     *
     * @param form - MultiValuedMap object containing the submitted form
     * @return - Response object containing
     */
    @POST
    @Path("/consent")
    @Consumes({MediaType.APPLICATION_FORM_URLENCODED, MediaType.MULTIPART_FORM_DATA})
    public Response postConsent(MultivaluedMap<String, String> form) {
        try {
            String originalRequest = form.get("orgConsentRequest").get(0);

            ConsentHandler consentHandler = new ConsentHandler(originalRequest, remoteJwksUri, keystorePath, keyAlias, keyPass, storePass, shouldEncryptConsentResponse, localIssuer);

            JWT orgConsentRequest = parseJwt(originalRequest);
            JWT consentRequestJwt = consentHandler.getConsentRequest();

            consentHandler.persistConsent(form);

            // generate the signed-then-encrypted (if encryption is enabled) or signed JWT to send back.
            String consentResponse = consentHandler.getConsentResponse(consentRequestJwt, orgConsentRequest);

            // if all of it was consented, then POST this towards the 'consentApprovalRedirectUri' inside the consent request.
            if (consentRequestJwt != null) {
                String postToURL = (String) consentRequestJwt.getJWTClaimsSet().getClaim("consentApprovalRedirectUri");
                return this.getConsentResponsePage(postToURL, consentResponse);
            }
        } catch (NullPointerException npe) {
            System.err.println("Unable to read orgConsentRequest from request: "+npe.getMessage());
        } catch (DecryptionException de) {
            System.err.println("Unable to decrypt the consent request: "+de.getMessage());
        } catch (InvalidJwt ij) {
            System.err.println("Unable to parse the consentRequest: "+ij.getMessage());
        } catch (ParseException pe) {
            System.err.println("Unable to retrieve the JWT claims from the consent request: "+pe.getMessage());
        }

        return Response.status(Response.Status.NOT_FOUND).entity("uh-oh").build();
    }


    /**
     * Generates the form to grant consent. If session data is enabled, data for the relevant claims is shown.
     *
     * @param consentRequest
     * @param originalConsentRequest
     * @return
     */
    private Response getConsentRequestPage(JWT consentRequest, String originalConsentRequest, Map<String, Consent> alreadyConsented, String username, Cookie sessionCookie) {
        Map<String, Object> sessionData = new HashMap<>();
        if (shouldRetrieveDataFromSession && sessionCookie != null) {
            sessionData = this.getSessionData(sessionCookie);
        }

        try {
            Map<String, String> mergedClaimsAndScopes = new HashMap((Map<String, String>) consentRequest.getJWTClaimsSet().getClaims().get("claims"));
            mergedClaimsAndScopes.putAll((Map<String, String>) consentRequest.getJWTClaimsSet().getClaims().get("scopes"));

            Map<String, JSONObject> mergedClaims = new HashMap((Map<String, JSONObject>) consentRequest.getJWTClaimsSet().getClaims().get("claims"));
            Map<String, String> mergedScopes = new HashMap((Map<String, String>) consentRequest.getJWTClaimsSet().getClaims().get("scopes"));

            StringBuilder rawHtml = new StringBuilder();
            rawHtml.append("<html><head><h1>Please give your consent</h1></head><body>");
            rawHtml.append("<form action=\"/rest/rcs/consent\" method=\"post\" name=\"scopeForm\">");
            rawHtml.append("<b>This service is requesting access to the following scope information for user \"" + ESAPI.encoder().encodeForHTML(username) + "\":</b><br/>");

            for (String claimName : mergedScopes.keySet()) {
                Object claimData = null;
                try {
                    claimData = sessionData.get(claimName);
                } catch (NullPointerException e) {
                }

                if (claimData == null) {
                    System.err.println("no sessionData associated with claim " + claimName + " - may need to configure the session property whitelist service if this is not expected");
                }

                String claimDisplayName = mergedClaimsAndScopes.get(claimName);
                if (claimDisplayName == null) {
                    claimDisplayName = claimName;
                }
                String checkboxState = "unchecked";
                if (alreadyConsented != null && alreadyConsented.size() > 0 && alreadyConsented.get(claimName) != null) {
                    checkboxState = "checked";
                    claimDisplayName = alreadyConsented.get(claimName).getConsentedClaimDisplay();
                }
                rawHtml.append("<input type=\"checkbox\" id=\"" + claimName + "\" value=\"" + claimName + "\" " + checkboxState + " name=\"" + claimName + "\" />");
                rawHtml.append("<label for=\"" + claimName + "\">" + claimDisplayName + "</label><br/>");
                if (claimData != null) {
                    rawHtml.append("<br>This claim contains the following data: <br/>" + claimData + "<br/>");
                }
            }

            rawHtml.append("<b>This service is requesting access to the following claim information for user \"" + ESAPI.encoder().encodeForHTML(username) + "\":</b><br/>");
            for (String requestedOps : mergedClaims.keySet()) {
                JSONObject claim = mergedClaims.get(requestedOps);

                for (Map.Entry<String, Object> claimEntry : claim.entrySet()) {
                    String claimDisplayName = claimEntry.getKey();

                    Object claimData = null;
                    try {
                        claimData = sessionData.get(claimEntry.getKey());
                    } catch (NullPointerException e) {
                    }

                    if (claimData == null) {
                        System.err.println("no sessionData associated with claim "+claimEntry.getKey()+" - may need to configure the session property whitelist service if this is not expected");
                    }

                    String checkboxState = "unchecked";
                    if (alreadyConsented != null && alreadyConsented.size() > 0 && alreadyConsented.get(claimEntry.getKey()) != null) {
                        checkboxState = "checked";
                        claimDisplayName = alreadyConsented.get(claimEntry.getKey()).getConsentedClaimDisplay();
                    }
                    rawHtml.append("<input type=\"checkbox\" id=\""+claimEntry.getKey()+"\" value=\""+claimEntry.getKey()+"\" "+checkboxState+" name=\""+claimEntry.getKey()+"\" />");
                    rawHtml.append("<label for=\""+claimEntry.getKey()+"\">"+claimDisplayName+"</label><br/>");
                    if (claimData != null) {
                        // this just displays the raw JSON
                        rawHtml.append("<br>This claim contains the following data: <br/>" + claimData + "<br/>");
                    }
                }
            }

            String safeOriginalConsentRequest = ESAPI.encoder().encodeForHTMLAttribute(originalConsentRequest);

            rawHtml.append("<input type=\"hidden\" value=\""+safeOriginalConsentRequest+"\" name=\"orgConsentRequest\"></input>");
            rawHtml.append("<input type=\"submit\" value=\"Sign\" name=\"submit\"></input></form></body></html>");

            return Response.status(Response.Status.OK).entity(rawHtml.toString()).build();
        } catch (ParseException pe) {
            System.err.println("Unable to parse claims from JWT: "+pe.getMessage());
        }
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("claims could not be parsed.").build();
    }


    /**
     * Generates a page showing that all consent has been granted, with a submit button to continue the flow.
     *
     * @param consentRequest
     * @param originalConsentRequest
     * @param alreadyConsented
     * @return
     */
    private Response getConsentAlreadyDonePage(JWT consentRequest, String originalConsentRequest, Map<String, Consent> alreadyConsented, String username) {

        StringBuilder rawHtml = new StringBuilder();
        rawHtml.append("<html><head><h1>All consent granted</h1></head><body>");
        rawHtml.append("<form action=\"/rest/rcs/consent\" method=\"post\" name=\"scopeForm\">");
        rawHtml.append("<b>This service has previously requested access to the following information for user \""+ESAPI.encoder().encodeForHTML(username)+"\":</b><br/>");

        if (alreadyConsented != null && alreadyConsented.size() > 0) {
            for (String claimName : alreadyConsented.keySet()) {
                String claimDisplayName;

                try {
                    claimDisplayName = alreadyConsented.get(claimName).getConsentedClaimDisplay();
                    if (claimDisplayName == null) {
                        claimDisplayName = claimName;
                    }
                } catch (NullPointerException npe) {
                    claimDisplayName = claimName;
                }
                rawHtml.append("<div><b>" + claimDisplayName + "</b></div>");
            }
        }

        rawHtml.append("<input type=\"hidden\" value=\""+ESAPI.encoder().encodeForHTMLAttribute(originalConsentRequest)+"\" name=\"orgConsentRequest\"></input>");
        rawHtml.append("<input type=\"submit\" value=\"Continue\" name=\"submit\"></input></form></body></html>");

        return Response.status(Response.Status.OK).entity(rawHtml.toString()).build();
    }


    /**
     * Generates the raw HTML response for a self-submitting form that posts back to the original AS.
     *
     * This is a sample implementation and should be styled/changed according to your preferences.
     *
     * @param postToURL
     * @param consentResponse
     * @return
     */
    private Response getConsentResponsePage(String postToURL, String consentResponse) {
        String safePostToURL = ESAPI.encoder().encodeForHTML(postToURL);
        String safeConsentResponse = ESAPI.encoder().encodeForHTML(consentResponse);

        if (safePostToURL != null && safeConsentResponse != null) {
            StringBuffer rawHtmlResponse = new StringBuffer();

            rawHtmlResponse.append("<html><body onload=\"document.consent_result.submit()\">");
            rawHtmlResponse.append("<form method=\"POST\" action=\"" + safePostToURL + "\" name=\"consent_result\">");
            rawHtmlResponse.append("<input type=\"hidden\" name=\"consent_response\" value=\"" + safeConsentResponse + "\" />");
            rawHtmlResponse.append("</form></body></html>");

            return Response.status(Response.Status.OK).entity(rawHtmlResponse.toString()).build();
        }

        return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("consent_response and postURL could not be validated.").build();
    }


    /**
     *
     * @param sessionCookie
     * @return
     */
    private Map<String, Object> getSessionData(Cookie sessionCookie) {
        Map<String, Object> sessionData = new HashMap<>();
        try {
            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL(this.sessionService).openConnection();

            httpURLConnection.setRequestMethod(HttpMethod.POST);
            httpURLConnection.setReadTimeout(5000);
            httpURLConnection.setConnectTimeout(5000);
            httpURLConnection.setInstanceFollowRedirects(false);
            httpURLConnection.addRequestProperty("Content-Type", "application/json");
            httpURLConnection.addRequestProperty("Accept", "*");
            httpURLConnection.addRequestProperty("Accept-API-Version", "protocol=1.0,resource=2.0");
            httpURLConnection.addRequestProperty("Cookie", sessionCookie.getName()+"="+sessionCookie.getValue());

            httpURLConnection.setDoOutput(true);
            OutputStreamWriter wr = new OutputStreamWriter(httpURLConnection.getOutputStream());
            wr.write("");
            wr.flush();

            int response = httpURLConnection.getResponseCode();

            StringBuilder vpdBuffer = new StringBuilder();
            try {
                String line;
                BufferedReader rd = new BufferedReader(new InputStreamReader(httpURLConnection.getInputStream()));
                while ((line = rd.readLine()) != null) {
                    vpdBuffer.append(line);
                }
            } catch (IOException e) {
                System.out.println(e.getMessage() + ", token invalid");
                return Collections.EMPTY_MAP;
            }

            JsonFactory factory = mapper.getFactory();
            JsonParser jsonParser = factory.createParser(vpdBuffer.toString());
            JsonNode node = mapper.readTree(jsonParser);

            sessionData = mapper.convertValue(node, Map.class);

        } catch (MalformedURLException mue) {
            System.out.println("Unable to use URL \""+this.sessionService+"\" to retrieve session information: "+mue.getMessage());
        } catch (IOException ioe) {
            System.out.println("Unable to contact service \""+this.sessionService+"\" due to: "+ioe.getMessage());
        }
        return sessionData;
    }
}
