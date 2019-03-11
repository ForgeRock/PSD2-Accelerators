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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;

import org.apache.http.HttpEntity;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class EidasCertificateStatusFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(EidasCertificateStatusFilter.class);

	private String certificateVerificationURL;
	private String authorization;
	private String fiReferenceId;

	@Override
	public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
		logger.info("Starting EidasCertificateStatusFilter.");

		String certificateVerificationResponse = "";
		String reqCertificate = request.getHeaders().getFirst("tpp-signature-certificate");
		if (reqCertificate.isEmpty()) {
			Response response = new Response(Status.UNAUTHORIZED);
			return Promises.newResultPromise(response);
		}

		CloseableHttpClient httpClient = HttpClientBuilder.create().build();
		try {
			HttpGet req = new HttpGet(certificateVerificationURL);
			req.addHeader("content-type", "application/json");
			req.addHeader("Accept", "application/json");
			req.addHeader("x-eidas", reqCertificate);
			req.addHeader("fi_reference_id", fiReferenceId);
			req.addHeader("Authorization", "Basic " + authorization);
			logger.info("Authorization: " + "Basic " + authorization);
			logger.info("fi_reference_id: " + fiReferenceId);

			CloseableHttpResponse rsp = httpClient.execute(req);
			logger.info("Response status: " + rsp.getStatusLine());
			HttpEntity entity = rsp.getEntity();
			if (rsp.getStatusLine().getStatusCode() != 200 || entity == null) {
				Response response = new Response(Status.UNAUTHORIZED);
				return Promises.newResultPromise(response);
			}

			InputStream instream = entity.getContent();
			String result = convertStreamToString(instream);
			logger.info("Response from Konsentus: " + result);
			instream.close();

			certificateVerificationResponse = result;

		} catch (Exception ex) {
			ex.printStackTrace();
		} finally {
			try {
				httpClient.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}

		ObjectMapper mapper = new ObjectMapper();
		JsonNode responseNode = null;
		try {
			responseNode = mapper.readTree(certificateVerificationResponse.toString());
		} catch (IOException e) {
			e.printStackTrace();
		}
		if (responseNode != null) {
			JsonNode validityNode = responseNode.get("data").get("eIDAS").get("data").get("validity");
			boolean validQTSP = validityNode.get("validQTSP").asBoolean();
			boolean validSignature = validityNode.get("validSignature").asBoolean();
			boolean notRevoked = validityNode.get("notRevoked").asBoolean();
			boolean notExpired = validityNode.get("notExpired").asBoolean();
			if (!validQTSP || !validSignature || !notRevoked || !notExpired) {
				logger.error("Certificate is invalid: ");
				logger.error("validQTSP: " + validQTSP);
				logger.error("validSignature: " + validSignature);
				logger.error("notRevoked: " + notRevoked);
				logger.error("notExpired: " + notExpired);
				Response response = new Response(Status.UNAUTHORIZED);
				return Promises.newResultPromise(response);
			}
		}

		logger.info("Finished EidasCertificateStatusFilter.");
		return next.handle(context, request);
	}

	private static String convertStreamToString(InputStream is) {

		BufferedReader reader = new BufferedReader(new InputStreamReader(is));
		StringBuilder sb = new StringBuilder();

		String line = null;
		try {
			while ((line = reader.readLine()) != null) {
				sb.append(line + "\n");
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			try {
				is.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		return sb.toString();
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
			EidasCertificateStatusFilter filter = new EidasCertificateStatusFilter();
			filter.certificateVerificationURL = config.get("certificateVerificationURL")
					.as(evaluatedWithHeapProperties()).required().asString();
			filter.authorization = config.get("authorization").as(evaluatedWithHeapProperties()).required().asString();
			filter.fiReferenceId = config.get("fiReferenceId").as(evaluatedWithHeapProperties()).required().asString();
			return filter;
		}
	}

}