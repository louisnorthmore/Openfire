package org.jivesoftware.openfire.plugin;

import org.apache.commons.httpclient.Header;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.PostMethod;
import org.jivesoftware.admin.AuthCheckFilter;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

/**
 * A servlet that acts as a utility method for WSO2-based bearer token functionality.
 *
 * This was created as a development tool, and never intended to be used in production!
 *
 * This servlet:
 * <ol>
 *     <li>Requests a Grant from WSO2.
 *         <p>This will cause WSO2 to redirect the browser to a login and/or confirmation page. WSO2's OAUTH configuration
 *         should have the path of this servlet as the callback URL. This will ensure that the browser is redirected to
 *         this Servlet with the grant code, when the grant is issued.</p>
 *     </li>
 *     <li>Using the grant, request an access token.
 *         <p>Using the grant code (that's passed as a query parameter in the request URL), an access token is requested
 *         from WSO2. The result of this call is presented in the response.</p>
 *     </li>
 * </ol>
 *
 * It is important that the exact path on which this servlet is accesses is used as the OAUTH callback url in the
 * WSO2-IS Service Provider configuration. Be aware: the trailing slash absense or presence is significant!
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class OAuthServlet extends HttpServlet
{
    private final Logger Log = LoggerFactory.getLogger( OAuthServlet.class );

    @Override
    public void init(ServletConfig servletConfig) throws ServletException {
        super.init(servletConfig);
        // Exclude this servlet from requering the user to login
        AuthCheckFilter.addExclude( "keycloak/oauth" );
    }

    protected void doPost( HttpServletRequest request, HttpServletResponse response ) throws ServletException, IOException
    {
        final String serverUrl = JiveGlobals.getProperty( "keycloak.url", "http://localhost:8080/auth" );
        final String realm = JiveGlobals.getProperty( "keycloak.realm", "amisnuage" );
        final String clientId = JiveGlobals.getProperty( "keycloak.clientid", "openfire" );
        final String clientSecret = JiveGlobals.getProperty( "keycloak.clientsecret", "6817c4a7-7cbb-4fe1-9182-cf61b28f71ed" );
        final String username = request.getParameter( "username" );
        final String password = request.getParameter( "password" );
        //--data grant_type=password&client_id=openfire&client_secret=6817c4a7-7cbb-4fe1-9182-cf61b28f71ed&username=admin&password=admin
        //
        //http://localhost:8080/auth/realms/amisnuage/protocol/openid-connect/token

        PostMethod method = null;
        try
        {
            method = new PostMethod( serverUrl + "/realms/" + realm + "/protocol/openid-connect/token");
            method.addParameter( "grant_type", "password" );
            method.addParameter( "client_id", clientId );
            method.addParameter( "client_secret", clientSecret );
            method.addParameter( "username", username );
            method.addParameter( "password", password );

            final HttpClient client = new HttpClient();
            final int status = client.executeMethod( method );

            response.setContentType( "text/html" );
            final PrintWriter writer = response.getWriter();
            writer.println( "<html><head><meta name=\"decorator\" content=\"none\"/></head><body>");
            writer.println( "<h1>Generate OAuth Bearer token</h1>");
            writer.println( "<p><a href=\""+ request.getRequestURI() +"\">Back to login form.</a></p>");
            writer.println( "<p>Below is the Keycloak response to a request for token generation.</p>");
            writer.println();
            writer.println( "<h2>Response (status "+status+") headers</h2><table>" );
            for ( Header responseHeader : method.getResponseHeaders() )
            {
                writer.println( "<tr>");
                writer.println( "<th>"+responseHeader.getName()+"</th>");
                writer.println( "<td>"+responseHeader.getValue() + "</tr>");
                writer.println( "<tr>");
            }
            writer.println( "</table>");

            writer.println( "<h2>Body</h2>" );
            writer.println( "<code>" + method.getResponseBodyAsString() + "</code>" );
            writer.println( "</body></html>" );
            writer.close();
        }
        finally
        {
            if ( method != null )
            {
                method.releaseConnection();
            }
        }

    }
    protected void doGet( HttpServletRequest request, HttpServletResponse response ) throws ServletException, IOException
    {
        final PrintWriter writer = response.getWriter();
        writer.println( "<html><head><meta name=\"decorator\" content=\"none\"/></head><body>");
        writer.println( "<h1>Generate OAuth Bearer token</h1>");
        writer.println( "<p>To Generate an OAuth Bearer token, please fill out this form.</p>");
        writer.println( "<form method=\"post\">" );
        writer.println( "<label for=\"username\">Username</label>&nbsp;<input type=\"text\" id=\"username\" name=\"username\"/><br/>" );
        writer.println( "<label for=\"password\">Password</label>&nbsp;<input type=\"password\" id=\"password\" name=\"password\"/><br/>" );
        writer.println( "<input type=\"submit\"/>" );
        writer.println( "<form>" );
        writer.close();
    }
}
