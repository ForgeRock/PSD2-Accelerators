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
package org.forgerock.openig.nextgenpsd2.filter;

import java.io.IOException;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.JsonValue;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.heap.Name;
import org.forgerock.openig.secrets.FileSystemSecretStoreHeaplet;
import org.forgerock.openig.secrets.SecretsUtils;
import org.forgerock.secrets.GenericSecret;
import org.forgerock.secrets.SecretStore;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class NextGenPSD2RegisterTppForwardFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(NextGenPSD2RegisterTppForwardFilter.class);

	private String idmURL;
	private String openIdmPassword;
	private String openIdmUsername;

	@Override
	public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
		logger.info("Starting NextGenPSD2RegisterTppForwardFilter.");
		try {
			logger.info("Request body when entering: " + request.getEntity().getString());
			String clientId = (String) context.asContext(AttributesContext.class).getAttributes().get("client_id");
			String clientName = (String) context.asContext(AttributesContext.class).getAttributes().get("client_name");
			ObjectMapper mapper = new ObjectMapper();
			JsonNode rootNode = mapper.createObjectNode();
			((ObjectNode) rootNode).put("name", clientName);
			((ObjectNode) rootNode).put("identifier", clientId);
			String jsonString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(rootNode);
			logger.info("Output JSON to provision IDM: " + jsonString);

			CloseableHttpClient httpClient = HttpClientBuilder.create().build();
			try {
				HttpPost requestToIDM = new HttpPost(idmURL);
				StringEntity params = new StringEntity(jsonString);
				requestToIDM.addHeader("content-type", "application/json");
				requestToIDM.addHeader("X-OpenIDM-Password", openIdmPassword);
				requestToIDM.addHeader("X-OpenIDM-Username", openIdmUsername);
				requestToIDM.setEntity(params);
				CloseableHttpResponse rsp = httpClient.execute(requestToIDM);
				logger.info("Response status: " + rsp.getStatusLine());
				logger.info("Response entity: " + rsp.getEntity());
			} catch (Exception ex) {
				ex.printStackTrace();
			} finally {
				httpClient.close();
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		logger.info("Finished NextGenPSD2RegisterTppForwardFilter.");
		return next.handle(context, request);
	}

	/**
	 * Create and initialize the filter, based on the configuration. The filter
	 * object is stored in the heap.
	 */
	public static class Heaplet extends GenericHeaplet {

		private Logger logger = LoggerFactory.getLogger(Heaplet.class);

		/**
		 * Create the filter object in the heap, setting the header name and value for
		 * the filter, based on the configuration.
		 *
		 * @return The filter object.
		 * @throws HeapException Failed to create the object.
		 */
		@SuppressWarnings("unchecked")
		@Override
		public Object create() throws HeapException {
			NextGenPSD2RegisterTppForwardFilter filter = new NextGenPSD2RegisterTppForwardFilter();
			filter.idmURL = config.get("idmURL").as(evaluatedWithHeapProperties()).required().asString();
			filter.openIdmPassword = config.get("openIdmPassword").as(evaluatedWithHeapProperties()).required()
					.asString();
			filter.openIdmUsername = config.get("openIdmUsername").as(evaluatedWithHeapProperties()).required()
					.asString();
			try {
				try {
					final FileSystemSecretStoreHeaplet heaplet = new FileSystemSecretStoreHeaplet();
					final JsonValue evaluated = config.as(evaluatedWithHeapProperties());
					final SecretStore<GenericSecret> store = (SecretStore<GenericSecret>) heaplet
							.create(Name.of("NextGenPSD2RegisterTppForwardFilter"), config, heap);
					if (store != null) {
						String password = SecretsUtils.getPasswordSecretIdOrPassword(heaplet.getSecretService(),
								evaluated.get("passwordSecretId"), evaluated.get("passwordSecretId"), logger);
						logger.info("The decoded password found in the FileSystemSecretStore: " + password);
					}
				} catch (Exception e) {
					e.printStackTrace();
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
			return filter;
		}
	}
}