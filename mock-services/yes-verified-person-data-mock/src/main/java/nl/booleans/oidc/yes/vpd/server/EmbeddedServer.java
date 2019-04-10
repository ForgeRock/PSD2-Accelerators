/*
 *  Copyright 2019 ForgeRock
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
 */
package nl.booleans.oidc.yes.vpd.server;

import java.net.URI;
import java.net.URL;
import java.security.ProtectionDomain;

import javax.ws.rs.core.UriBuilder;

import org.eclipse.jetty.server.Handler;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.handler.ContextHandler;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerCollection;
import org.eclipse.jetty.server.handler.ResourceHandler;
import org.glassfish.jersey.jetty.JettyHttpContainerFactory;
import org.glassfish.jersey.server.ResourceConfig;

public final class EmbeddedServer {

	private static final int SERVER_PORT = 8789;

	private EmbeddedServer() {
	}

	public static void main(String[] args) throws Exception {
		URI baseUri = UriBuilder.fromUri("http://localhost").port(SERVER_PORT).build();
		ResourceConfig config = new ResourceConfig(VerifiedPersonDataService.class);

		Server server = JettyHttpContainerFactory.createServer(baseUri, config, false);

		ContextHandler contextHandler = new ContextHandler("/rest");

		contextHandler.setHandler(server.getHandler());
		
		ProtectionDomain protectionDomain = EmbeddedServer.class.getProtectionDomain();
		URL location = protectionDomain.getCodeSource().getLocation();
		
		ResourceHandler resourceHandler = new ResourceHandler();
		resourceHandler.setWelcomeFiles(new String[] { "index.html" });
		resourceHandler.setResourceBase(location.toExternalForm());
		System.out.println(location.toExternalForm());
		HandlerCollection handlerCollection = new HandlerCollection();
		handlerCollection.setHandlers(new Handler[] { resourceHandler, contextHandler, new DefaultHandler() });
		server.setHandler(handlerCollection);
		server.start();
		server.join();
	}
}
