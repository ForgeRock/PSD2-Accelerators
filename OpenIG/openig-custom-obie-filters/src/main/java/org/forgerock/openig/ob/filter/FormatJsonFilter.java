package org.forgerock.openig.ob.filter;

import static org.forgerock.openig.el.Bindings.bindings;

import java.io.IOException;

import org.forgerock.http.Filter;
import org.forgerock.http.Handler;
import org.forgerock.http.protocol.Message;
import org.forgerock.http.protocol.Request;
import org.forgerock.http.protocol.Response;
import org.forgerock.openig.el.Bindings;
import org.forgerock.openig.heap.GenericHeaplet;
import org.forgerock.openig.heap.HeapException;
import org.forgerock.services.context.Context;
import org.forgerock.util.promise.NeverThrowsException;
import org.forgerock.util.promise.Promise;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

public class FormatJsonFilter implements Filter {

	private Logger logger = LoggerFactory.getLogger(FormatJsonFilter.class);

	@Override
	public Promise<Response, NeverThrowsException> filter(Context context, Request request, Handler next) {
		logger.info("Start FormatJsonFilter.");
		Promise<Response, NeverThrowsException> promise = next.handle(context, request);
		return promise.thenOnResult(response -> process(response, bindings(context, request, response)));
	}

	private void process(Message<?> message, Bindings bindings) {
		String json = null;
		try {
			json = message.getEntity().getString();
			logger.info("Input Json: " + json);
		} catch (IOException e) {
			e.printStackTrace();
		}

		if (json != null) {
			String outputJson = formatJson(json);
			logger.info("Output Json: " + outputJson);
			message.getHeaders().remove("Content-Encoding");
			message.setEntity(outputJson);
		} else {
			logger.info("Output Json empty.");
		}
	}

	private String formatJson(String json) {
		if (json != null) {
			ObjectMapper mapper = new ObjectMapper();
			ObjectNode node = null;
			try {
				node = (ObjectNode) mapper.readTree(json);
			} catch (IOException e) {
				e.printStackTrace();
			}

			if (node != null && node.get("_id") != null) {
				node.remove("_id");
			}

			if (node != null && node.get("_rev") != null) {
				node.remove("_rev");
			}
			return node.toString();
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
			FormatJsonFilter filter = new FormatJsonFilter();
			return filter;
		}
	}

}
