package com.inteno.iopsys.plugin.oauthresourceserver;

import org.keycloak.KeycloakSecurityContext;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A servlet that exposes private user information. This implementation depends on the existence of a Keycloak security
 * context, such as the one added by the Keycloak OIDC filter.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class ResourceServlet extends HttpServlet
{
    protected void doGet( HttpServletRequest request, HttpServletResponse response ) throws ServletException, IOException
    {
        final KeycloakSecurityContext securityContext = (KeycloakSecurityContext) request.getAttribute( KeycloakSecurityContext.class.getName() );

        if ( securityContext == null || securityContext.getToken() == null )
        {
            response.setStatus( HttpServletResponse.SC_UNAUTHORIZED );
            return;
        }

        if ( !securityContext.getToken().getRealmAccess().isUserInRole( "iopsys-gateway-access" ) )
        {
            response.setStatus( HttpServletResponse.SC_FORBIDDEN );
            return;
        }

        response.setStatus( HttpServletResponse.SC_OK );
    }
}
