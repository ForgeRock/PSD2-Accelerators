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
package com.forgerock.openbanking.aspsp.rs.rcs.web.rest;

import java.util.List;

import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ConsentRequest;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.ConsentResponse;
import com.forgerock.openbanking.aspsp.rs.rcs.model.consent.Empty;
import com.forgerock.openbanking.aspsp.rs.rcs.model.rcs.ModelApiResponse;
import com.forgerock.openbanking.aspsp.rs.rcs.model.rcs.RedirectionAction;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import io.swagger.annotations.ApiResponse;
import io.swagger.annotations.ApiResponses;
@javax.annotation.Generated(value = "io.swagger.codegen.languages.SpringCodegen", date = "2019-01-24T23:01:14.780Z")

@Api(value = "api", description = "the api API")
public interface ConsentApi {

    @ApiOperation(value = "Public JSON Token Key ", nickname = "apiConsentJwkPubGet", notes = "", response = ModelApiResponse.class, tags={ "jwk_pub", })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "succeful operation", response = ModelApiResponse.class) })
    @RequestMapping(value = "/api/rcs/consent/jwk_pub",
        produces = { "application/json" }, 
        method = RequestMethod.GET)
    ResponseEntity<String> apiConsentJwkPubGet();
    

    @ApiOperation(value = "Show signed and decypted JWT from AM", nickname = "getConsentfromAM", notes = "Show Scope and claims in RCS", response = ConsentResponse.class, tags={ "consent", })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "successful operation", response = ConsentResponse.class),
        @ApiResponse(code = 400, message = "Invalid ID supplied"),
        @ApiResponse(code = 404, message = "Consent not found") })
    @RequestMapping(value = "/api/rcs/consent",
        produces = { "application/json" }, 
        method = RequestMethod.GET)
    ResponseEntity<ConsentResponse> getAMConsent(@NotNull @ApiParam(value = "Get Scope from AM", required = true) @Valid @RequestParam(value = "consent_request", required = true) String consentRequest)throws Exception;


    @ApiOperation(value = "Post consent to the AM", nickname = "sendConsent", notes = "", response = Empty.class, tags={ "sendconsent", })
    @ApiResponses(value = { 
        @ApiResponse(code = 200, message = "200 response", response = Empty.class),
        @ApiResponse(code = 302, message = "302 response"),
        @ApiResponse(code = 405, message = "Invalid input") })
    @RequestMapping(value = "/api/rcs/consent/sendconsent",
        produces = { "application/json" }, 
        consumes = { "application/json" },
        method = RequestMethod.POST)
    ResponseEntity<RedirectionAction> sendConsent(@ApiParam(value = "Consnet Request Object" ,required=true )  @Valid @RequestBody ConsentRequest consentRequest,
    		@CookieValue(value = "${application.am-cookie-name}", required = false) String ssoToken);

    
}