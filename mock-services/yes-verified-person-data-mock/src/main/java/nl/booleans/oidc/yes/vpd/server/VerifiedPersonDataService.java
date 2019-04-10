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
package nl.booleans.oidc.yes.vpd.server;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.LinkedHashMap;

@Path("/vpd")
public class VerifiedPersonDataService {
    @POST
    @Path("/get_verified_person_data")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response getVerifiedPersonData(@Context HttpHeaders headers, LinkedHashMap body) {
        String json = "{\n" +
                "  \"verification\": {\n" +
                "    \"organization\": \"Bank Y\",\n" +
                "    \"legal_context\": {\n" +
                "      \"country\": \"DE\",\n" +
                "      \"regulation\": \"Geldwäschegesetz\"\n" +
                "    },\n" +
                "    \"date\": \"2013-02-21\",\n" +
                "    \"id\": \"676q3636461467647q8498785747q487\",\n" +
                "    \"method\": \"qes\",\n" +
                "    \"qes\": {\n" +
                "      \"issuer\": \"de_bdr\",\n" +
                "      \"certificate_id\": \"7367636467467154561546614\"\n" +
                "    }\n" +
                "  },\n" +
                "  \"claims\": {\n" +
                "    \"given_name\": \"Max\",\n" +
                "    \"family_name\": \"Meier\",\n" +
                "    \"birthdate\": \"1956-01-28\",\n" +
                "    \"https://www.yes.com/claims/place_of_birth\": {\n" +
                "      \"country\": \"DE\",\n" +
                "      \"city\": \"Musterstadt\"\n" +
                "    },\n" +
                "    \"https://www.yes.com/claims/nationality\": \"DE\",\n" +
                "    \"address\": {\n" +
                "      \"locality\": \"Maxstadt\",\n" +
                "      \"postal_code\": \"12344\",\n" +
                "      \"country\": \"DE\",\n" +
                "      \"street\": \"An der Sanddüne 22\"\n" +
                "    }\n" +
                "  }\n" +
                "}";
        return Response.status(200).entity(json).build();
    }
}
