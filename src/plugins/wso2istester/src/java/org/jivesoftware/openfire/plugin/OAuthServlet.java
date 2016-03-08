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

    /**
     * The scheme (protocol) over which the SOAP interaction takes place. Defaults to 'https'.
     */
    public static final String SERVICE_SCHEME = "wso2is.service.scheme";

    /**
     * The network/server name where the WSO2-IS web interface can be reached. Defaults to 'localhost'.
     */
    public static final String SERVICE_HOSTNAME = "wso2is.service.hostname";

    /**
     * The TCP port on which the WSO2-IS web interface can be reached. Defaults to '9443'.
     */
    public static final String SERVICE_PORT = "wso2is.service.port";

    /**
     * The OAuth Client Key that identifies our server (as a service provider) in WSO2-IS.
     */
    public static final String OAUTH_CLIENT_KEY = "wso2is.oauth.client.key";

    /**
     * The OAuth Client Secret that authenticates our server (as a service provider) in WSO2-IS.
     */
    public static final String OAUTH_CLIENT_SECRET = "wso2is.oauth.client.secret";

    @Override
    public void init(ServletConfig servletConfig) throws ServletException {
        super.init(servletConfig);
        // Exclude this servlet from requering the user to login
        AuthCheckFilter.addExclude( "wso2istester/oauth" );
    }

    protected void doGet( HttpServletRequest request, HttpServletResponse response ) throws ServletException, IOException
    {
        final String serviceScheme = JiveGlobals.getProperty( SERVICE_SCHEME, "https" );
        final String serviceHostname = JiveGlobals.getProperty( SERVICE_HOSTNAME, "localhost" );
        final String servicePort = JiveGlobals.getProperty( SERVICE_PORT, "9443" );
        final String responseType = "code";
        final String clientKey = JiveGlobals.getProperty( OAUTH_CLIENT_KEY, "iiPsRcxhUAQ3ULcWJTUK2CRzlwwa" );
        final String clientSecret = JiveGlobals.getProperty( OAUTH_CLIENT_SECRET, "9EmJ4Y5jN60W6BBj_nNa7Rcx20Ia" );
        final String callbackUrl = request.getRequestURL().toString(); // Must be the URL (minus query) of this servlet! Something like this is expected: "http://localhost:9090/plugins/wso2istester/oauth";

        final String code = request.getParameter( "code" ); // This is the authorization grant!
        if ( code == null || code.isEmpty() )
        {
            Log.info( "No Authorization Grant in the request. Redirect to WSO2 authorize endpoint to obtain a grant (WSO2 will redirect back to us with an Authorzation Grant code!)" );
            response.sendRedirect( serviceScheme + "://" + serviceHostname + ":" + servicePort + "/oauth2/authorize?response_type=" + responseType + "&client_id=" + clientKey + "&redirect_uri=" + callbackUrl );
        }
        else
        {
            Log.info( "Found an Authorization Grant in the request. Using it to obtain an Access Token from WSO2." );
            PostMethod method = null;
            try
            {
                method = new PostMethod( serviceScheme + "://" + serviceHostname + ":" + servicePort + "/oauth2/token" );
                method.addParameter( "grant_type", "authorization_code" );
                method.addParameter( "code", code );
                method.addParameter( "redirect_uri", callbackUrl );
                method.addParameter( "client_id", clientKey );
                method.addParameter( "client_secret", clientSecret );

                final HttpClient client = new HttpClient();
                final int status = client.executeMethod( method );

                response.setContentType( "text/html" );
                final PrintWriter writer = response.getWriter();
                writer.println( "<html><head><meta name=\"decorator\" content=\"none\"/></head><body>");
                writer.println( "<p>Request to WSO2 'authorize' responded with: " + status + "</p>");
                writer.println( "<p><a href=\""+ request.getRequestURI() +"\">Restart entire call (re-request grant)</a></p>");
                writer.println();
                writer.println( "<h2>Headers</h2><table>" );
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
    }
}
