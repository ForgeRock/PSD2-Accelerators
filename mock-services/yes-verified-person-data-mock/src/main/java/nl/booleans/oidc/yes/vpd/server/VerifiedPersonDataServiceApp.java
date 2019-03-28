package nl.booleans.oidc.yes.vpd.server;

import org.glassfish.jersey.server.ResourceConfig;

public class VerifiedPersonDataServiceApp extends ResourceConfig {

	public VerifiedPersonDataServiceApp() {
		packages("nl.booleans.oidc.yes.vpd");
	}
}
