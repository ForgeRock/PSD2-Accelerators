/***************************************************************************
 *  Copyright 2019 ForgeRock AS.
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
import org.forgerock.http.protocol.*;

def responseJson = (attributes.responseJson).toString()
def amUri = attributes.amUri
def igUri = attributes.igUri
def rsp = new Response (Status.OK)

println "[DEBUG] responseJson original: " + responseJson

if (responseJson != null && amUri != null && igUri != null){ 
	//Replace authorize hostname
	//responseJson = responseJson.replace(amUri + "/authorize", igUri + "/authorize")

	//Replace access_token hostname
	//responseJson = responseJson.replace(amUri + "/access_token", igUri + "/access_token")

	//Replace register hostname
	//responseJson = responseJson.replace(amUri + "/register", igUri + "/register")

	//Replace issuer hostname
    //responseJson = responseJson.replace("\"issuer\":\"" + amUri + "\"", "\"issuer\":\"" + igUri + "\"")

	//Replace introspect hostname
    responseJson = responseJson.replace(igUri + "/introspect", amUri + "/introspect")

    //Replace userinfo hostname
    responseJson = responseJson.replace(igUri + "/userinfo", amUri + "/userinfo")

	rsp.entity = responseJson
}
return rsp
