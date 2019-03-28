package nl.booleans.oidc.yes.vpd.server;

import javax.ws.rs.Consumes;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.LinkedHashMap;

@Path("/mediation")
public class MediationRecordsService {
    @POST
    @Path("/record")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response consumeMediationRecord(@Context HttpHeaders headers, LinkedHashMap body) {
        System.out.println("received incoming data: "+body);
        return Response.status(200).entity(body).build();
    }
}