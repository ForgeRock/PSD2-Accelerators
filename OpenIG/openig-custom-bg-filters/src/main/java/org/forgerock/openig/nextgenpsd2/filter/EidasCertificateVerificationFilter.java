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

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
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
import com.fasterxml.jackson.databind.node.ObjectNode;

public class EidasCertificateVerificationFilter implements Filter {
	private Logger logger = LoggerFactory.getLogger(EidasCertificateVerificationFilter.class);
	private static final Base64 base64 = new Base64(true);

	@Override
	public Promise<Response, NeverThrowsException> filter(final Context context, final Request request,
			final Handler next) {
		logger.info("Starting EidasCertificateVerificationFilter.");

		JsonNode rootNode = mapEntityBody(request);
		String encodedTppCert = request.getHeaders().getFirst("tpp-signature-certificate");
		if (rootNode.isNull() || encodedTppCert.isEmpty()) {
			Response response = new Response(Status.UNAUTHORIZED);
			return Promises.newResultPromise(response);
		}

		String clientId = "";
		String clientName = "";

		byte[] decoded = base64.decode((encodedTppCert.getBytes()));
		logger.info("Decoded: " + decoded);
		String subjectDN = "";
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decoded));
			if (certificate != null) {
				logger.info("Subject DN from certificate: " + certificate.getSubjectDN());
				String certificatePrincipal = certificate.getSubjectDN().toString();
				subjectDN = certificatePrincipal;
				Map<String, String> subjectDnMap = new HashMap<String, String>();
				String[] pairs = certificatePrincipal.split(",");
				for (String pair : pairs) {
					String[] keyValue = pair.split("=");
					subjectDnMap.put(keyValue[0].trim(), keyValue[1]);
					if (keyValue[0].contains("OID")) {
						clientId = keyValue[1];
					}
				}
				clientName = subjectDnMap.get("CN");
			}
		} catch (Exception e) {
			logger.error("Invalid certificate: " + encodedTppCert);
			e.printStackTrace();
			Response response = new Response(Status.UNAUTHORIZED);
			return Promises.newResultPromise(response);
		}

		ObjectNode o = (ObjectNode) rootNode;
		if (subjectDN != null && clientName != null && clientId != null) {
			o.put("client_name", clientName);
			o.put("tls_client_auth_subject_dn", subjectDN);
			context.asContext(AttributesContext.class).getAttributes().put("client_id", clientId);
			context.asContext(AttributesContext.class).getAttributes().put("client_name", clientName);
		}
		logger.info("Request Body modified: " + rootNode.toString());
		request.setEntity(rootNode.toString());
		logger.info("Finished EidasCertificateVerificationFilter.");
		return next.handle(context, request);
	}

	private JsonNode mapEntityBody(Request request) {
		JsonNode rootNode = null;
		try {
			ObjectMapper mapper = new ObjectMapper();
			rootNode = mapper.readTree(request.getEntity().getString());
			logger.info("Request Body to be modified: " + rootNode.toString());
		} catch (Exception e) {
			logger.error("Invalid or NULL request body.");
			e.printStackTrace();
		}
		return rootNode;
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
			EidasCertificateVerificationFilter filter = new EidasCertificateVerificationFilter();
			return filter;
		}
	}
}