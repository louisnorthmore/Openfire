package org.jivesoftware.openfire.plugin;

import org.apache.axis2.client.Options;
import org.apache.axis2.client.Stub;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.authenticator.stub.LoginAuthenticationExceptionException;
import org.wso2.carbon.authenticator.stub.LogoutAuthenticationExceptionException;

import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;

/**
 * Provides stubs for WSO2 Identity Service SOAP endpoints.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class WSO2ISServiceStub
{
    private static final Logger Log = LoggerFactory.getLogger( WSO2ISServiceStub.class );

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
     * A username that identifies a user that is authorized to invoke the WSO2-IS administrative and OAuth validation SOAP services.
     */
    public static final String ADMINSERVICE_USERNAME = "wso2is.adminservice.username";

    /**
     * A password that authenticates a user that is authorized to invoke the WSO2-IS administrative and OAuth validation SOAP services.
     */
    public static final String ADMINSERVICE_PASSWORD = "wso2is.adminservice.password";

    private String adminUser;
    private String adminPassword;

    private String serviceScheme;
    private String serviceHostname;
    private String servicePort;

    protected String cookie;
    private String endpointAuthentication;
    protected String endpointTokenValidation;

    public void initialize()
    {
        adminUser = JiveGlobals.getProperty( ADMINSERVICE_USERNAME );
        adminPassword = JiveGlobals.getProperty( ADMINSERVICE_PASSWORD );
        serviceScheme = JiveGlobals.getProperty( SERVICE_SCHEME, "https" );
        serviceHostname = JiveGlobals.getProperty( SERVICE_HOSTNAME, "localhost" );
        servicePort = JiveGlobals.getProperty( SERVICE_PORT, "9443" );

        try
        {
            if ( !login() )
            {
                Log.warn( "Authentication to the WSO2 IS administrative services has failed. Please verify the admin username and password." );
            }
        }
        catch ( RemoteException | LoginAuthenticationExceptionException | MalformedURLException ex )
        {
            Log.warn( "Authentication to the WSO2 IS administrative services has failed.", ex );
        }
    }

    public void dispose() throws RemoteException, LogoutAuthenticationExceptionException
    {
        try
        {
            logout();
        }
        finally
        {
            this.endpointTokenValidation = null;
            this.endpointAuthentication = null;
            this.serviceScheme = null;
            this.serviceHostname = null;
            this.servicePort = null;
            this.adminPassword = null;
            this.adminUser = null;
            this.cookie = null;
        }
    }

    protected boolean login() throws RemoteException, LoginAuthenticationExceptionException, MalformedURLException
    {
        this.endpointAuthentication = new URL( serviceScheme, serviceHostname, Integer.parseInt( servicePort ), "/services/AuthenticationAdmin.AuthenticationAdminHttpsSoap12Endpoint/" ).toExternalForm();
        this.endpointTokenValidation = new URL( serviceScheme, serviceHostname, Integer.parseInt( servicePort ), "/services/OAuth2TokenValidationService.OAuth2TokenValidationServiceHttpsSoap12Endpoint/" ).toExternalForm();

        final AuthenticationAdminStub authenticationAdminStub = new AuthenticationAdminStub( this.endpointAuthentication );

        if ( authenticationAdminStub.login( adminUser, adminPassword, serviceHostname ) )
        {
            ServiceContext serviceContext = authenticationAdminStub._getServiceClient().getLastOperationContext().getServiceContext();
            this.cookie = (String) serviceContext.getProperty( HTTPConstants.COOKIE_STRING );
            return true;
        }
        else
        {
            return false;
        }
    }

    protected void logout() throws RemoteException, LogoutAuthenticationExceptionException
    {
        if ( this.cookie != null )
        {
            final AuthenticationAdminStub authenticationAdminStub = new AuthenticationAdminStub( this.endpointAuthentication );
            authenticationAdminStub.logout();
            this.cookie = null;
        }
    }

    protected void addCookie( Stub stub ) {
        final Options options = stub._getServiceClient().getOptions();
        options.setManageSession( true );
        options.setProperty( org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie );
    }
}