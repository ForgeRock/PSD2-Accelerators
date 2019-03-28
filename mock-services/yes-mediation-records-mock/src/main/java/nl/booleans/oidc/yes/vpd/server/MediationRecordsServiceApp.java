package nl.booleans.oidc.yes.vpd.server;

import org.glassfish.jersey.server.ResourceConfig;

public class MediationRecordsServiceApp extends ResourceConfig {

	public MediationRecordsServiceApp() {
		packages("nl.booleans.oidc.yes.vpd");
	}
}
