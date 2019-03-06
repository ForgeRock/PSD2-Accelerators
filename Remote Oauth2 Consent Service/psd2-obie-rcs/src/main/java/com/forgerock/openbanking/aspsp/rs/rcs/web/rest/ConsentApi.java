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

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import com.forgerock.openbanking.aspsp.rs.rcs.model.rcs.ModelApiResponse;

import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
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
    
}