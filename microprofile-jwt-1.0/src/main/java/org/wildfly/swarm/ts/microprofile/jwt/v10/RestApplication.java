package org.wildfly.swarm.ts.microprofile.jwt.v10;

import org.eclipse.microprofile.auth.LoginConfig;

import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

@LoginConfig(authMethod = "MP-JWT", realmName = "thorntail-cmd-client")
@ApplicationPath("/app")
public class RestApplication extends Application {
}
