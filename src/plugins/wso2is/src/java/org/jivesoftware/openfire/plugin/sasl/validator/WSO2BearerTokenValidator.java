package org.jivesoftware.openfire.plugin.sasl.validator;

import org.apache.axis2.client.Options;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.jivesoftware.openfire.plugin.WSO2ISServiceStub;
import org.jivesoftware.openfire.plugin.sasl.ServerErrorResponse;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.authenticator.stub.AuthenticationAdminStub;
import org.wso2.carbon.authenticator.stub.LoginAuthenticationExceptionException;
import org.wso2.carbon.authenticator.stub.LogoutAuthenticationExceptionException;
import org.wso2.carbon.identity.oauth2.stub.OAuth2TokenValidationServiceStub;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_OAuth2AccessToken;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationRequestDTO_TokenValidationContextParam;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationResponseDTO;

import java.net.MalformedURLException;
import java.net.URL;
import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Map;

/**
 * A validator for OAuth 2.0 bearer tokens (as described in RFC6750) that relays validation to a WSO2 Identity Server
 * instance.
 *
 * This implementation uses SOAP 1.2 to interact with various WSO2-IS services. The SOAP implementation is provided by
 * stub implementations that ship with WSO2-IS. This implementation is compatible with version WSO2-IS v5.1.0.
 *
 * When interacting with WSO2-IS via HTTPS, it is typically needed to either add its client certificates in the
 * default trust store of your JVM, or add a WSO2-IS provided trust store to your JVM. An example of the latter:
 * <tt>
 *   System.setProperty( "javax.net.ssl.trustStore", "/home/guus/Downloads/wso2is-5.1.0/repository/resources/security/wso2carbon.jks" );
 *   System.setProperty( "javax.net.ssl.trustStorePassword", "wso2carbon" );
 *   System.setProperty( "javax.net.ssl.trustStoreType", "JKS" );
 * </tt>
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class WSO2BearerTokenValidator extends WSO2ISServiceStub
{
    private final static Logger Log = LoggerFactory.getLogger( WSO2BearerTokenValidator.class );

    public OAuth2TokenValidationResponseDTO validate( String auth, String host, String port, String mthd, String path, String post, String qs ) throws RemoteException, LoginAuthenticationExceptionException, MalformedURLException
    {
        String identifier = auth.substring( "Bearer ".length() );
        String tokenType = "Bearer";
        Map<String, String> context = new HashMap<String, String>();
        String[] requiredClaimURIs = null;

        Log.trace( "Validating token..." ); // Do not write bearer tokens to logfiles! That's as bad as writing passwords to logfiles.
        final OAuth2TokenValidationResponseDTO response = validate( identifier, tokenType, context, requiredClaimURIs, true );

        if ( response.getValid() )
        {
            Log.debug( "Token is valid. Authorized user: '{}', expiry time: {}.", response.getAuthorizedUser(), response.getExpiryTime() );
        }
        else
        {
            Log.debug( "Validation of token failed. Error message: {}", response.getErrorMsg() );
        }
        return response;
    }

    protected OAuth2TokenValidationResponseDTO validate( String identifier, String tokenType, Map<String, String> context, String[] requiredClaimURIs, boolean allowAuthRefresh ) throws RemoteException, LoginAuthenticationExceptionException, MalformedURLException
    {
        // Access Token
        final OAuth2TokenValidationRequestDTO_OAuth2AccessToken accessTokenDTO = new OAuth2TokenValidationRequestDTO_OAuth2AccessToken();
        accessTokenDTO.setIdentifier( identifier );
        accessTokenDTO.setTokenType( tokenType );

        // Context
        OAuth2TokenValidationRequestDTO_TokenValidationContextParam[] contextDTO;
        if ( context == null || context.isEmpty() )
        {
            contextDTO = null;
        }
        else
        {
            contextDTO = new OAuth2TokenValidationRequestDTO_TokenValidationContextParam[ context.size() ];
            int i = 0;
            for ( Map.Entry<String, String> entry : context.entrySet() )
            {
                final OAuth2TokenValidationRequestDTO_TokenValidationContextParam contextParam = new OAuth2TokenValidationRequestDTO_TokenValidationContextParam();
                contextParam.setKey( entry.getKey() );
                contextParam.setValue( entry.getValue() );

                contextDTO[ ++i ] = contextParam;
            }
        }

        // Required Claim URIs
        final String[] requiredClaimURIsDTO = requiredClaimURIs;

        // Create request
        final OAuth2TokenValidationRequestDTO request = new OAuth2TokenValidationRequestDTO();
        request.setAccessToken( accessTokenDTO );
        request.setContext( contextDTO );
        request.setRequiredClaimURIs( requiredClaimURIsDTO );

        // Execute service
        try
        {
            if (cookie == null) {
                allowAuthRefresh = false;
                login();
            }
            final OAuth2TokenValidationServiceStub serviceStub = new OAuth2TokenValidationServiceStub( this.endpointTokenValidation );
            final Options options = serviceStub._getServiceClient().getOptions();
            options.setManageSession( true );
            options.setProperty( org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie );
            return serviceStub.validate( request );
        }
        catch ( RemoteException ex )
        {
            // Perhaps the cookie has expired?
            if ( allowAuthRefresh )
            {
                login();
                return validate( identifier, tokenType, context, requiredClaimURIs, false ); // recurse (once).
            }
            else
            {
                throw ex;
            }
        }
    }
}

