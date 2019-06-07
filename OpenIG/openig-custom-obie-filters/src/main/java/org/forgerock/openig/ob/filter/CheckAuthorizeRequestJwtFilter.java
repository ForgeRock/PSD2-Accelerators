package org.forgerock.openig.ob.filter;

import java.util.HashMap;
import java.util.Map;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.MutableUri;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.http.protocol.Status;
import org.forgerock.json.jose.jwt.Jwt;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.openig.tools.JwtUtil;
import org.forgerock.services.context.AttributesContext;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.forgerock.util.promise.Promises;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CheckAuthorizeRequestJwtFilter implements Filter {
	private Logger logger = LoggerFactory.getLogger(CheckAuthorizeRequestJwtFilter.class);
	private String mandatoryClaims;

	@Override
	public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
		String[] mandatoryClaimsArray = mandatoryClaims.split(",");
		logger.info("mandatoryClaimsArray: " + mandatoryClaimsArray);
		MutableUri uri = request.getUri();
		logger.info("uri: " + uri);
		String uriQuery = uri.getQuery();
		logger.info("uriQuery: " + uriQuery);

		String state = null;

		String finalUri = uri.toString().split("\\?")[0];
		if (uriQuery != null && uriQuery.contains("request")) {
			Map<String, String> queryMap = new HashMap<String, String>();
			String[] pairs = uriQuery.split("&");
			for (int i = 0; i < pairs.length; i++) {
				String pair = pairs[i];
				String[] keyValue = pair.split("=");
				queryMap.put(keyValue[0], keyValue[1]);
			}

			logger.info("queryMap: " + queryMap);

			if (queryMap != null && queryMap.size() > 0) {
				String jwtString = queryMap.get("request");
				logger.info("jwtString: " + jwtString);
				if (jwtString != null && !jwtString.isEmpty()) {
					Jwt jwt = JwtUtil.reconstructJwt(jwtString, Jwt.class);
					if (jwt != null) {
						String claimsMissing = checkClaimsArePresent(mandatoryClaimsArray, jwt);
						if (claimsMissing == null) {
							state = jwt.getClaimsSet().getClaim("state").toString();
							logger.info("state: " + state);
							if (state != null && !state.isEmpty()) {
								context.asContext(AttributesContext.class).getAttributes().put("jwtState", state);
								return next.handle(context, request);
							}
						} else {
							if (jwt.getClaimsSet().getClaim("state") != null) {
								state = jwt.getClaimsSet().getClaim("state").toString();
							}
							logger.info("state: " + state);
							String redirectUrl = buildRedirectUri(finalUri, claimsMissing, state);
							logger.info("redirectUrl: " + redirectUrl);
							context.asContext(AttributesContext.class).getAttributes().put("jwtState", state);
							context.asContext(AttributesContext.class).getAttributes().put("normalizedLocation",
									redirectUrl);
							request.getHeaders().add("Location", redirectUrl);
							Response response = new Response(Status.FOUND);
							return Promises.newResultPromise(response);
						}
					}
				}
				if (queryMap.get("state") != null) {
					state = queryMap.get("state");
				}
			}
		}

		String redirectUrl = buildRedirectUri(finalUri, "request", state);
		logger.info("redirectUrl: " + redirectUrl);
		context.asContext(AttributesContext.class).getAttributes().put("jwtState", state);
		context.asContext(AttributesContext.class).getAttributes().put("normalizedLocation", redirectUrl);
		Response response = new Response(Status.FOUND);
		return Promises.newResultPromise(response);
	}

	private String buildRedirectUri(String baseUri, String missingClaim, String state) {
		if (state != null) {
			return baseUri + "#error_description=Invalid%20request%20parameter%20" + missingClaim + "&state=" + state
					+ "&error=invalid_request_object";
		} else {
			return baseUri + "#error_description=Invalid%20request%20parameter%20" + missingClaim
					+ "&error=invalid_request_object";
		}
	}

	private String checkClaimsArePresent(String[] mandatoryClaimsArray, Jwt jwt) {
		for (String claim : mandatoryClaimsArray) {
			if (jwt.getClaimsSet().getClaim(claim) == null) {
				return claim;
			}
		}
		return null;
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
			CheckAuthorizeRequestJwtFilter filter = new CheckAuthorizeRequestJwtFilter();
			filter.mandatoryClaims = config.get("mandatoryClaims").as(evaluatedWithHeapProperties()).required()
					.asString();
			return filter;
		}
	}
}