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

def responseLocation = attributes.responseLocation
def jwtState = attributes.jwtState
println "[DEBUG GROOVY] INPUT responseLocation: " + responseLocation + " - state from request jwt: " + jwtState

if (responseLocation  != null && responseLocation.contains('?') && responseLocation.contains('error_description=')){ 
	originalUri = attributes.originalUri
	println "[DEBUG GROOVY] INPUT originalUri: " + originalUri

	fragmentLocation = responseLocation.replace('?', '#')
	println "[DEBUG GROOVY] INPUT fragmentLocation: " + fragmentLocation
	
	if (! responseLocation.contains('state=')){

		if (jwtState != null && jwtState != ""){
			fragmentLocation += "&state=" + jwtState;
		}

		println "[DEBUG GROOVY] OUTPUT fragmentLocation (appended state): " + fragmentLocation
		attributes.normalizedLocation = fragmentLocation;
	}
	else {
		println "[DEBUG GROOVY] OUTPUT fragmentLocation (initial state): " + fragmentLocation
		attributes.normalizedLocation = fragmentLocation;
	}
}
else {
	attributes.normalizedLocation = responseLocation;
}
return new Response(Status.FOUND)
