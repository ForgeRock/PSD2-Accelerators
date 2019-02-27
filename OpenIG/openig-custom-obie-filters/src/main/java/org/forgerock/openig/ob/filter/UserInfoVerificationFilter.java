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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class UserInfoVerificationFilter implements Filter {

	private String userInfoURL;

	private Logger logger = LoggerFactory.getLogger(UserInfoVerificationFilter.class);

	@Override
	public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
		String bearer = request.getHeaders().getFirst("Authorization");
		logger.info("Request bearer: " + bearer);
		HttpURLConnection connection = null;
		ObjectMapper mapper = new ObjectMapper();
		JsonNode userInfo = mapper.createObjectNode();
		try {
			URL myurl = new URL(userInfoURL);
			connection = (HttpURLConnection) myurl.openConnection();
			connection.setDoOutput(true);
			connection.setRequestMethod("POST");
			connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
			connection.setRequestProperty("Authorization", bearer);
			logger.info("Response code: " + connection.getResponseCode());
			if (connection.getResponseCode() != 200) {
				Response response = new Response(Status.UNAUTHORIZED);
				return Promises.newResultPromise(response);
			}
			StringBuilder content;
			try (BufferedReader in = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {

				String line;
				content = new StringBuilder();

				while ((line = in.readLine()) != null) {
					content.append(line);
				}

				userInfo = mapper.readTree(content.toString());
			} catch (Exception e1) {
				e1.printStackTrace();
			}

		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			connection.disconnect();
		}
		logger.info("Intent Id: " + userInfo.get("openbanking_intent_id").asText());
		context.asContext(AttributesContext.class).getAttributes().put("openbankingIntentId", userInfo.get("openbanking_intent_id").asText());
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
			UserInfoVerificationFilter filter = new UserInfoVerificationFilter();
			filter.userInfoURL = config.get("userInfoURL").as(evaluatedWithHeapProperties()).required().asString();
			return filter;
		}
	}
}