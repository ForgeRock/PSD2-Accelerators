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

import static org.forgerock.openig.el.Bindings.bindings;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Message;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.openig.el.Bindings;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.tools.JwtUtil;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class RegisterTppForwardFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(RegisterTppForwardFilter.class);

	private String idmURL;
	private String openIdmPassword;
	private String openIdmUsername;

	@Override
	public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
		logger.info("Starting RegisterTppForwardFilter.");
		String password = (String) context.asContext(AttributesContext.class).getAttributes().get(openIdmPassword);
		Promise<Response, NeverThrowsException> promise = next.handle(context, request);
		return promise
				.thenOnResult(response -> process(response, bindings(context, request, response), context, password));
	}

	private void process(Message<?> message, Bindings bindings, Context context, String password) {
		logger.info("openIdmPassword: " + openIdmPassword);
		if (password == null) {
			logger.info("Password null on response");
		}
		ObjectNode amNode = null;
		try {
			String entity = message.getEntity().getString();
			if (entity != null) {
				ObjectMapper mapper = new ObjectMapper();
				try {
					amNode = (ObjectNode) mapper.readTree(entity);
					logger.debug("AM response: " + amNode.toString());
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		} catch (IOException e2) {
			e2.printStackTrace();
		}
		boolean error = false;
		String errorString = "";
		ObjectMapper mapper = new ObjectMapper();
		try {
			if (amNode != null) {
				String ssa = "";
				String softwareClientId = "";
				String softwareClientName = "";
				String certId = "certId";
				if (amNode.get("software_statement") != null) {
					ssa = amNode.get("software_statement").asText();
					Jwt ssaJwt = JwtUtil.reconstructJwt(ssa, Jwt.class);
					if (ssaJwt != null && ssaJwt.getClaimsSet().getClaim("org_id") != null) {
						certId = ssaJwt.getClaimsSet().getClaim("org_id").toString();
					}
				}
				if (amNode.get("client_id") != null) {
					softwareClientId = amNode.get("client_id").asText();
				}
				if (amNode.get("client_name") != null) {
					softwareClientName = amNode.get("client_name").asText();
				}

				JsonNode rootNode = mapper.createObjectNode();
				if (softwareClientName.isEmpty()) {
					((ObjectNode) rootNode).put("name", softwareClientId);
				} else {
					((ObjectNode) rootNode).put("name", softwareClientName);
				}
				((ObjectNode) rootNode).put("identifier", softwareClientId);
				((ObjectNode) rootNode).put("ssa", ssa);
				((ObjectNode) rootNode).put("certId", certId);
				String jsonString = mapper.writerWithDefaultPrettyPrinter().writeValueAsString(rootNode);
				logger.info("Output JSON: " + jsonString);

				CloseableHttpClient httpClient = HttpClientBuilder.create().build();

				try {
					HttpPost requestToIDM = new HttpPost(idmURL);
					StringEntity params = new StringEntity(jsonString);
					requestToIDM.addHeader("content-type", "application/json");
					requestToIDM.addHeader("X-OpenIDM-Password", password);
					requestToIDM.addHeader("X-OpenIDM-Username", openIdmUsername);
					requestToIDM.setEntity(params);
					CloseableHttpResponse rsp = httpClient.execute(requestToIDM);
					logger.info("Response status: " + rsp.getStatusLine());
					if (rsp.getStatusLine().getStatusCode() == 201) {
						JsonNode node = null;
						StringBuilder content;
						try (BufferedReader in = new BufferedReader(
								new InputStreamReader(rsp.getEntity().getContent()))) {
							String line;
							content = new StringBuilder();
							while ((line = in.readLine()) != null) {
								content.append(line);
							}
							if (content.toString() != null) {
								logger.info("Read content: " + content.toString());
								node = mapper.readTree(content.toString());
							}
						} catch (Exception e1) {
							e1.printStackTrace();
						}

						if (node != null) {
							int code = node.get("result").get("code").asInt();
							logger.info("Code: " + code);
							if (code != 201) {
								error = true;
								errorString = node.get("result").get("reason").asText();
								logger.info("Error String: " + errorString);
							}
						}
					}
				} catch (Exception ex) {
					ex.printStackTrace();
				} finally {
					httpClient.close();
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (error) {
			JsonNode rootNode = mapper.createObjectNode();
			((ObjectNode) rootNode).put("reason", errorString);
			message.setEntity(rootNode.toString());
		}
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
			RegisterTppForwardFilter filter = new RegisterTppForwardFilter();
			filter.idmURL = config.get("idmURL").as(evaluatedWithHeapProperties()).required().asString();
			filter.openIdmPassword = config.get("openIdmPassword").as(evaluatedWithHeapProperties()).required()
					.asString();
			filter.openIdmUsername = config.get("openIdmUsername").as(evaluatedWithHeapProperties()).required()
					.asString();
			return filter;
		}
	}
}