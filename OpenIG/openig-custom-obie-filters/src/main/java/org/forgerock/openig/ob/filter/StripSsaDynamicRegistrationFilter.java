/***************************************************************************
 *  Copyright 2019 ForgeRock AS
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
package org.forgerock.openig.ob.filter;

import java.io.IOException;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.tools.JwtUtil;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class StripSsaDynamicRegistrationFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(StripSsaDynamicRegistrationFilter.class);

	private Boolean stripSSA;

	@Override
	public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
		logger.debug("Starting RegisterTppForwardFilter.");
		ObjectNode node = null;
		try {
			String jwt = request.getEntity().getString();
			Jwt registrationJwt = JwtUtil.reconstructJwt(jwt, Jwt.class);
			String claims = registrationJwt.getClaimsSet().build();
			ObjectMapper mapper = new ObjectMapper();

			Jwt ssaJwt = null;
			if (registrationJwt != null) {
				ssaJwt = JwtUtil.reconstructJwt(
						registrationJwt.getClaimsSet().getClaim("software_statement").toString(), Jwt.class);
			}

			try {
				node = (ObjectNode) mapper.readTree(claims);
				if (stripSSA != null && stripSSA) {
					if (node.get("software_statement") != null) {
						node.remove("software_statement");
					}
				}

				if (ssaJwt != null) {
					if (ssaJwt.getClaimsSet().getClaim("software_jwks_endpoint") != null) {
						String jwksUri = ssaJwt.getClaimsSet().getClaim("software_jwks_endpoint").toString();
						node.put("public_key_selector", "jwks_uri");
						node.put("jwks_uri", jwksUri);
					}

					if (ssaJwt.getClaimsSet().getClaim("software_client_name") != null) {
						String softwareClientName = ssaJwt.getClaimsSet().getClaim("software_client_name").toString();
						node.put("client_name", softwareClientName);
					}
				}

				logger.debug("Final JSON: " + node.toString());
			} catch (IOException e) {
				e.printStackTrace();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		request.getHeaders().clear();
		request.getHeaders().add("Content-Type", "application/json");
		request.setEntity(node.toString());
		return next.handle(context, request);
	}

	/**
	 * Create and initialize the filter, based on the configuration. The filter
	 * object is stored in the heap.
	 */
	public static class Heaplet extends GenericHeaplet {
		/**
		 * Create the filter object in the heap, setting the header name and value for
		 * the filter, based on the configuration.
		 *
		 * @return The filter object.
		 * @throws HeapException Failed to create the object.
		 */
		@Override
		public Object create() throws HeapException {
			StripSsaDynamicRegistrationFilter filter = new StripSsaDynamicRegistrationFilter();
			filter.stripSSA = config.get("stripSSA").as(evaluatedWithHeapProperties()).asBoolean();
			return filter;
		}
	}
}