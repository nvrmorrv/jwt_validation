package org.wildfly.swarm.ts.microprofile.jwt.v10;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.Claims;
import org.eclipse.microprofile.jwt.JsonWebToken;

import javax.annotation.security.DenyAll;
import javax.annotation.security.RolesAllowed;
import javax.inject.Inject;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.SecurityContext;
import java.util.Set;

@Path("/secured")
@DenyAll
public class SecuredResource {
    @Inject
    private JsonWebToken jwt;

    @Inject
    @Claim(standard = Claims.iss)
    private String issuer;

    @Inject
    @Claim(standard = Claims.groups)
    private Set<String> groups;

    @GET
    @RolesAllowed("*")
    public String hello(@Context SecurityContext security) {
        return "Hello, " + jwt.getName() + ", your token was issued by " + issuer + ", you are in groups " + groups;
    }
}
