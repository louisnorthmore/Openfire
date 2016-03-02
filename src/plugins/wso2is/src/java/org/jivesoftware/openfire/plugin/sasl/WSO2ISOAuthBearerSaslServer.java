package org.jivesoftware.openfire.plugin.sasl;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.plugin.sasl.validator.WSO2BearerTokenValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.authenticator.stub.LoginAuthenticationExceptionException;
import org.wso2.carbon.authenticator.stub.LogoutAuthenticationExceptionException;
import org.wso2.carbon.identity.oauth2.stub.dto.OAuth2TokenValidationResponseDTO;

import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import java.net.MalformedURLException;
import java.nio.charset.Charset;
import java.rmi.RemoteException;
import java.util.HashMap;
import java.util.Map;

/**
 * A SaslServer implementation of the OAuth SASL OAUTHBEARER mechanism, as specified by RFC 7628: "A Set of Simple
 * Authentication and Security Layer (SASL) Mechanisms for OAuth"
 *
 * This implementation makes use of a WSO2 Identity Server for token validation.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 * @see <a href="https://tools.ietf.org/html/rfc7628">RFC 7628</a>
 */
public class WSO2ISOAuthBearerSaslServer implements SaslServer
{
    private final static Logger Log = LoggerFactory.getLogger( WSO2ISOAuthBearerSaslServer.class );

    /**
     * The IANA-registered mechanism name of this implementation: "OAUTHBEARER"
     */
    public static final String MECHANISM_NAME = "OAUTHBEARER";
    private String authorizationID;

    private enum State {

        /** Initial state. Has not evaluated any response yet. */
        PRE_INITIAL_RESPONSE,

        /** An error has been returned in response to the initial response (waiting for client response). */
        SENT_ERROR,

        /** Done (authentication succeeded or failed). */
        COMPLETED
    }

    private State state = State.PRE_INITIAL_RESPONSE;

    private WSO2BearerTokenValidator validator;

    public WSO2ISOAuthBearerSaslServer()
    {
    }

    /**
     * Returns the IANA-registered mechanism name of this SASL server: "OAUTHBEARER".
     *
     * @return A non-null string representing the IANA-registered mechanism name: OAUTHBEARER
     */
    public String getMechanismName()
    {
        return MECHANISM_NAME;
    }

    public byte[] evaluateResponse( byte[] response ) throws SaslException
    {
        if( isComplete() )
        {
            throw new IllegalStateException( "OAUTHBEARER authentication was already completed." );
        }

        switch ( state )
        {
            case PRE_INITIAL_RESPONSE:

                final byte[] serverResponse = processInitialClientResponse( response );

                // The generated and to-be-returned server response is either contains an error message or is empty
                // (which indicates that authentication is successful).
                if ( serverResponse == null || serverResponse.length == 0 )
                {
                    state = State.COMPLETED;
                    return null;
                }
                else
                {
                    state = State.SENT_ERROR;
                    return serverResponse;
                }

            case SENT_ERROR:
                // A second client response is only expected when the server responded with an error message to the
                // initial response. The client MUST then send either an additional client response consisting of a
                // single %x01 (control A) character to the server in order to allow the server to finish the exchange
                // or a SASL abort message as generally defined in Section 3.5 of SASL [RFC4422].
                state = State.COMPLETED;
                throw new SaslException();

            default:
                throw new IllegalStateException( "Instance is in an unrecognized state (please report this incident as a bug in class: " + this.getClass().getCanonicalName() + "). Unrecognized value: " + state );
        }
    }

    public boolean isComplete()
    {
        return state == State.COMPLETED;
    }

    public String getAuthorizationID()
    {
        if( !isComplete() )
        {
            throw new IllegalStateException( "OAUTHBEARER authentication has not completed." );
        }

        return authorizationID;
    }

    public Object getNegotiatedProperty( String propName )
    {
        if( !isComplete() )
        {
            throw new IllegalStateException( "OAUTHBEARER authentication has not completed." );
        }

        if ( Sasl.QOP.equals( propName ) )
        {
            return "auth";
        }
        return null;
    }

    public void dispose() throws SaslException
    {
        state = null;
        authorizationID = null;

        if ( validator != null )
        {
            try
            {
                validator.dispose();
            }
            catch ( RemoteException | LogoutAuthenticationExceptionException ex )
            {
                throw new SaslException( "An exception occurred while disposing the token validator.", ex );
            }
            finally
            {
                validator = null;
            }
        }
    }

    public byte[] unwrap( byte[] incoming, int offset, int len ) throws SaslException
    {
        if( !isComplete() )
        {
            throw new IllegalStateException( "OAUTHBEARER authentication has not completed." );
        }

        throw new IllegalStateException( "OAUTHBEARER supports neither integrity nor privacy." );
    }

    public byte[] wrap( byte[] outgoing, int offset, int len ) throws SaslException
    {
        if( !isComplete() )
        {
            throw new IllegalStateException( "OAUTHBEARER authentication has not completed." );
        }

        throw new IllegalStateException( "OAUTHBEARER supports neither integrity nor privacy." );
    }

    /**
     * Processes the initial client response.
     *
     * https://tools.ietf.org/html/rfc7628#section-3.1: "Client responses are a GS2 [RFC5801] header followed by zero or
     * more key/value pairs, or it may be empty."
     *
     * Upon success, null is returned. When authentication fails, a JSON-based error message is returned (as a byte
     * array).
     *
     * @param response data provided by the client (cannot be null, should not be empty).
     * @return null if authentication was successful, or an error message.
     * @throws SaslException If an error occurred while processing the response or generating a challenge.
     */
    protected byte[] processInitialClientResponse( byte[] response ) throws SaslException
    {
        if ( response == null ) {
            throw new IllegalArgumentException( "Argument 'response' cannot be null." );
        }

        if ( response.length <= 1 )
        {
            // The client response consisting of only a single kvsep is used only when authentication fails and is only valid in that context.
            return "{\"status\":\"invalid_request\"}".getBytes( Charset.forName( "US-ASCII" ) );
        }

        final String decoded;
        try {
            decoded = new String( response, "UTF-8" );
        } catch ( Exception ex ) {
            throw new SaslException( "Unable to decode initial client response.", ex );
        }

        final String kvsep = "\u0001";
        final String[] parts = decoded.split( kvsep );

        // The client response consisting of only a single kvsep is used only when authentication fails and is only valid in that context.
        if ( parts.length == 0 ) {
            return "{\"status\":\"invalid_request\"}".getBytes( Charset.forName( "US-ASCII" ) );
        }

        final String requestedAuthorizationID;
        try {
            final GS2Header gs2Header = GS2Header.parse( parts[ 0 ] );
            requestedAuthorizationID = gs2Header.getAuthorizationIdentity();
        } catch ( IllegalArgumentException ex ) {
            throw new SaslException( "Unable to parse gs2-header.", ex );
        }

        // Process key/value pairs (pre-populated with default values)
        final Map<String, String> kv = new HashMap<String, String>();
        kv.put( "mthd", "POST" );
        kv.put( "path", "/" );
        kv.put( "post", "" );
        kv.put( "qs", "" );

        for ( int i = 1; i < parts.length ; i++ )
        {
            final String[] kvPair = parts[ i ].split( "=", 2 );
            if ( kvPair.length == 1 ) {
                kv.put( kvPair[0], null );
            }
            else if (kvPair.length == 2 ) {
                kv.put( kvPair[0], kvPair[1] );
            }
            else {
                throw new SaslException( "Unable to parse client-resp attribute from initial client response." );
            }
        }

        final String auth = kv.get( "auth" );
        final String host = kv.get( "host" );
        final String port = kv.get( "port" );
        final String mthd = kv.get( "mthd" );
        final String path = kv.get( "path" );
        final String post = kv.get( "post" );
        final String qs   = kv.get( "qs"   );

        if ( auth == null ) {
            throw new SaslException( "'auth' value is missing in initial client response." );
        }

        try
        {
            validator = new WSO2BearerTokenValidator();
            validator.initialize();
            final OAuth2TokenValidationResponseDTO soapResponse = validator.validate( auth, host, port, mthd, path, post, qs );
            if ( soapResponse.getValid() )
            {
                authorizationID = soapResponse.getAuthorizedUser();

                // TODO this stripping of the Carbon domain and adding of our own is somewhat simplistic. WSO should be configured properly instead.
                if ( authorizationID.contains( "@" ) )
                {
                    authorizationID = authorizationID.substring( 0, authorizationID.indexOf( '@' ) );
                }
                authorizationID += "@" + XMPPServer.getInstance().getServerInfo().getXMPPDomain();

                if (requestedAuthorizationID != null && !requestedAuthorizationID.equals( authorizationID  )) {
                    Log.warn( "Authorized user ID '{}' does not match requested user ID '{}'.", authorizationID, requestedAuthorizationID );
                    // TODO should we error on this?
                }
                Log.info( "Authorization of user ID '{}' successful.", authorizationID );
                return null;
            }
            else
            {
                Log.info( "Authorization failed. Requested userID (if any): '{}'.", requestedAuthorizationID );
                final ServerErrorResponse error = new ServerErrorResponse( soapResponse.getErrorMsg() );
                return error.toJson().getBytes( Charset.forName( "US-ASCII" ) );
            }
        }
        catch ( MalformedURLException | RemoteException | LoginAuthenticationExceptionException ex )
        {
            throw new SaslException( "An exception occurred while validating a token.", ex );
        }
    }
}
