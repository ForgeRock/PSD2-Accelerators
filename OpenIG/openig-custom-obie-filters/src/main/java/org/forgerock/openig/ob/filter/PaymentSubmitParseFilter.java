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
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public class PaymentSubmitParseFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(PaymentSubmitParseFilter.class);

	@Override
	public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
		String paymentSubmissionJson = "";
		try {
			String body = request.getEntity().getString();
			if (body != null && !body.isEmpty()) {
				ObjectMapper mapper = new ObjectMapper();
				JsonNode paymentSubmission = mapper.createObjectNode();
				paymentSubmission = mapper.readTree(body);
				JsonNode initiation = paymentSubmission.get("Data").get("Initiation");
				paymentSubmissionJson = initiation.toString();
				logger.info("payment_submission_json " + paymentSubmissionJson.trim());
				paymentSubmissionJson = paymentSubmissionJson.replaceAll("\\s+", "");
				context.asContext(AttributesContext.class).getAttributes().put("paymentSubmissionJson",
						hashPaymentSubmission(paymentSubmissionJson));
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
		return next.handle(context, request);
	}

	private String hashPaymentSubmission(String paymentSubmission) {
		logger.info("Input json on SHA-256: " + paymentSubmission);
		MessageDigest digest = null;
		try {
			digest = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		byte[] hash = digest.digest(paymentSubmission.getBytes(StandardCharsets.UTF_8));
		return bytesToHex(hash);
	}

	private String bytesToHex(byte[] hash) {
		StringBuffer hexString = new StringBuffer();
		for (int i = 0; i < hash.length; i++) {
			String hex = Integer.toHexString(0xff & hash[i]);
			if (hex.length() == 1)
				hexString.append('0');
			hexString.append(hex);
		}
		logger.info("Returning hashed value: " + hexString.toString());
		return hexString.toString();
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
			PaymentSubmitParseFilter filter = new PaymentSubmitParseFilter();
			return filter;
		}
	}

}
