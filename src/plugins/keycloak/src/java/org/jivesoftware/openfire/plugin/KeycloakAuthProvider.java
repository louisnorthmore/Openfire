package org.jivesoftware.openfire.plugin;

import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.ConnectionException;
import org.jivesoftware.openfire.auth.InternalUnauthenticatedException;
import org.jivesoftware.openfire.auth.UnauthorizedException;
import org.jivesoftware.openfire.plugin.sasl.keycloak.jaas.ConfigurableDirectAccessGrantsLoginModule;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.*;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.util.Collections;

/**
 * An auth provider that is backed by a Keycloak instance.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class KeycloakAuthProvider implements AuthProvider
{
    private static final Logger Log = LoggerFactory.getLogger( KeycloakAuthProvider.class );

    @Override
    public void authenticate( final String username, final String password ) throws UnauthorizedException, ConnectionException, InternalUnauthenticatedException
    {
        // This code uses the JAAS integration from Keycloak, but does not actually use JAAS properly to login. Instead,
        // the JAAS protocol flow is copied (somewhat) here. This circumvents a classloading issue that occurs when JAAS
        // is used directly (JAAS assumes that the classloader of the executing thread can be used, which won't work for
        // Openfire plugins).
        final ConfigurableDirectAccessGrantsLoginModule loginModule = new ConfigurableDirectAccessGrantsLoginModule();
        try
        {
            final Subject subject = new Subject();
            loginModule.initialize( subject, new CallbackHandler()
            {
                @Override
                public void handle( Callback[] callbacks ) throws IOException, UnsupportedCallbackException
                {
                    if ( callbacks != null )
                    {
                        for ( Callback callback : callbacks )
                        {
                            if ( callback instanceof NameCallback )
                            {
                                ( ( NameCallback ) callback ).setName( username );
                            }
                            if ( callback instanceof PasswordCallback )
                            {
                                ( (PasswordCallback) callback ).setPassword( password.toCharArray() );
                            }
                        }
                    }
                }
            }, Collections.<String,Object>emptyMap(), Collections.<String,Object>emptyMap());

            if ( loginModule.login() )
            {
                loginModule.commit();

                Log.trace( "Username/password combination was correct for username '{}'.", username );
                return;
            }
            else
            {
                loginModule.abort();
            }
        }
        catch ( Exception ex )
        {
            // Do not leak privacy-sensitive information by logging the exception!
            try
            {
                loginModule.abort();
            }
            catch ( LoginException e )
            {
                Log.warn( "Unable to abort login!" );
            }
        }

        Log.trace( "Username/password combination was incorrect for username '{}'.", username );
        throw new UnauthorizedException();

    }

    @Override
    public String getPassword( String username ) throws UserNotFoundException, UnsupportedOperationException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setPassword( String username, String password ) throws UserNotFoundException, UnsupportedOperationException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public boolean supportsPasswordRetrieval()
    {
        return false;
    }

    @Override
    public boolean isScramSupported()
    {
        return false;
    }

    public void dispose()
    {

    }

    /**
     * @deprecated this method is added only for backwards compatiblity to Openfire 4.0.1. It should be removed for Openfire 4.1 onwards.
     */
    @Override
    public boolean isPlainSupported()
    {
        return true;
    }

    /**
     * @deprecated this method is added only for backwards compatiblity to Openfire 4.0.1. It should be removed for Openfire 4.1 onwards.
     */
    @Override
    public boolean isDigestSupported()
    {
        return false;
    }

    /**
     * @deprecated this method is added only for backwards compatiblity to Openfire 4.0.1. It should be removed for Openfire 4.1 onwards.
     */
    @Override
    public void authenticate( String username, String token, String digest ) throws UnauthorizedException, ConnectionException, InternalUnauthenticatedException
    {
        throw new UnsupportedOperationException();
    }
}
