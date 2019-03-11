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

import static org.forgerock.openig.el.Bindings.bindings;

import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;

import org.apache.commons.codec.binary.Base64;
import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.openig.el.Expression;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CNFKeyVerifierFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(CNFKeyVerifierFilter.class);
	private static final Base64 base64 = new Base64(true);
	private Expression<LinkedHashMap> cnfKey;

	@Override
	public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
		logger.info("Starting CNFKeyVerifierFilter.");
		LinkedHashMap keyJson = (LinkedHashMap) cnfKey.eval(bindings(context, request));
		String cert = request.getHeaders().getFirst("ssl-client-cert");
		logger.info("Received certificate:" + cert);
		logger.info("Config CNF Key: " + keyJson);
		try {
			cert = java.net.URLDecoder.decode(cert, StandardCharsets.UTF_8.name());
			logger.info("Decoded" + new String(cert));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		cert = cert.replaceAll("-----BEGIN CERTIFICATE-----", "");
		cert = cert.replaceAll("-----END CERTIFICATE-----", "");
		byte[] sslClientCert = cert.getBytes();
		sslClientCert = base64.decode(sslClientCert);
		MessageDigest digest;
		String certCnfKey = "";
		try {
			digest = MessageDigest.getInstance("SHA-256");
			byte[] hash = digest.digest(sslClientCert);
			certCnfKey = new String(base64.encode(hash));
			logger.info("Encoded certificate CNF Key: " + certCnfKey);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		if (!certCnfKey.startsWith((String) keyJson.get("x5t#S256"))) {
			logger.info("Keys don't match: " + "configCnfKey=" + keyJson.get("x5t#S256") + " certCnfKey=" + certCnfKey);
			Response response = new Response(Status.UNAUTHORIZED);
			return Promises.newResultPromise(response);
		}
		logger.info("Finished CNFKeyVerifierFilter.");
		return next.handle(context, request);
	}

	public void setCnfKey(final Expression<LinkedHashMap> cnfKey) {
		this.cnfKey = cnfKey;
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
			CNFKeyVerifierFilter filter = new CNFKeyVerifierFilter();
			filter.setCnfKey(config.get("cnfKey").as(expression(LinkedHashMap.class)));
			return filter;
		}
	}

}
