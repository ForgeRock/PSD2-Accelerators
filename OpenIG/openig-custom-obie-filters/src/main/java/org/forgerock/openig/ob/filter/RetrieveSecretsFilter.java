package org.forgerock.openig.ob.filter;

import java.util.HashMap;
import java.util.Map;

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

public class RetrieveSecretsFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(RetrieveSecretsFilter.class);

	private Map<String, String> secretsMap;

	@Override
	public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
		logger.info("Secrets map: " + secretsMap);
		if (secretsMap != null && secretsMap.size() > 0) {
			for (Map.Entry<String, String> entry : secretsMap.entrySet()) {
				String key = entry.getKey();
				Object value = entry.getValue();
				context.asContext(AttributesContext.class).getAttributes().put(key, value);
			}
		}
		return next.handle(context, request);
	}

	public void setSecrets(final Map<String, String> secretsMap) {
		this.secretsMap = secretsMap;
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
			RetrieveSecretsFilter filter = new RetrieveSecretsFilter();
			try {
				logger.debug("Start heaplet.");
				final FileSystemSecretStoreHeaplet heaplet = new FileSystemSecretStoreHeaplet();
				final JsonValue evaluated = config.as(evaluatedWithHeapProperties());
				String secretIds = evaluated.get("passwordSecretIds").asString();
				secretIds = secretIds.replaceAll("\\s", "");
				logger.debug("Secret id's to retrieve as list: " + secretIds);
				String[] splitArrayOfSecrets = secretIds.split(",");
				final SecretStore<GenericSecret> store = (SecretStore<GenericSecret>) heaplet
						.create(Name.of("RetrieveSecretsFilter"), config, heap);
				logger.debug("Store: " + store);
				if (store != null && splitArrayOfSecrets != null && splitArrayOfSecrets.length > 0) {
					Map<String, String> secrets = new HashMap<String, String>();
					for (String secretId : splitArrayOfSecrets) {
						String password = SecretsUtils.getPasswordSecretIdOrPassword(heaplet.getSecretService(),
								JsonValue.json(secretId), JsonValue.json(secretId), logger);
						logger.debug("The decoded password found in the FileSystemSecretStore: " + password);
						secrets.put(secretId, password);
					}
					filter.setSecrets(secrets);
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
			logger.debug("End heaplet.");
			return filter;
		}
	}

}
