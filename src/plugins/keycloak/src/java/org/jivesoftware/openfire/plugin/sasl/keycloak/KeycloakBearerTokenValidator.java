package org.jivesoftware.openfire.plugin.sasl.keycloak;

import org.jivesoftware.openfire.plugin.sasl.BearerTokenValidator;
import org.jivesoftware.openfire.plugin.sasl.ValidationResult;
import org.jivesoftware.openfire.plugin.sasl.keycloak.jaas.ConfigurableBearerTokenLoginModule;
import org.jivesoftware.openfire.plugin.sasl.keycloak.jaas.KeycloakJaasConfiguration;
import org.jivesoftware.util.JiveGlobals;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.adapters.jaas.BearerTokenLoginModule;
import org.keycloak.admin.client.Keycloak;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.security.auth.spi.LoginModule;
import java.io.IOException;
import java.util.Collections;

/**
 * A validator of OAUTH Bearer tokens that uses a Keycloak instance.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class KeycloakBearerTokenValidator implements BearerTokenValidator
{
    private final static Logger Log = LoggerFactory.getLogger( KeycloakBearerTokenValidator.class );

    @Override
    public ValidationResult validate( final String auth, final String host, final String port, final String mthd, final String path, final String post, final String qs )
    {
        final String token = auth.substring( "Bearer ".length() );

        Log.trace( "Validation of bearer token '{}' starting...", token );

        // This code uses the JAAS integration from Keycloak, but does not actually use JAAS properly to login. Instead,
        // the JAAS protocol flow is copied (somewhat) here. This circumvents a classloading issue that occurs when JAAS
        // is used directly (JAAS assumes that the classloader of the executing thread can be used, which won't work for
        // Openfire plugins).
        final BearerTokenLoginModule loginModule = new ConfigurableBearerTokenLoginModule();
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
                            if ( callback instanceof PasswordCallback )
                            {
                                ( (PasswordCallback) callback ).setPassword( token.toCharArray() );
                            }
                        }
                    }
                }
            }, Collections.<String,Object>emptyMap(), Collections.<String,Object>emptyMap());

            if ( loginModule.login() )
            {
                loginModule.commit();

                Log.trace( "Validation of bearer token '{}' successful.", token );

                // Note that Keycloak defaults to the user-id for the principal name. We'll have to dig a little deeper for the actual username.
                final KeycloakPrincipal principal = (KeycloakPrincipal) subject.getPrincipals().iterator().next();
                final String username = principal.getKeycloakSecurityContext().getToken().getPreferredUsername();
                return ValidationResult.success( username );
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

        Log.debug( "Validation of bearer token '{}' failed.", token );
        return ValidationResult.failure( "invalid_token" );

        /* This is the 'proper' JAAS way of doing things, but incompatible with Openfire plugin classloading
        try
        {
            final LoginContext lc = new LoginContext( KeycloakJaasConfiguration.NAME, new CallbackHandler()
            {
                @Override
                public void handle( Callback[] callbacks ) throws IOException, UnsupportedCallbackException
                {
                    if ( callbacks != null )
                    {
                        for ( Callback callback : callbacks )
                        {
                            if ( callback instanceof PasswordCallback )
                            {
                                ( (PasswordCallback) callback ).setPassword( token.toCharArray() );
                            }
                        }
                    }
                }
            } );

            lc.login();
            Log.trace( "Validation of bearer token '{}' successful.", token );
            return ValidationResult.success( lc.getSubject().getPrincipals().iterator().next().getName() );
        }
        catch ( LoginException ex )
        {
            Log.debug( "Validation of bearer token '{}' failed.", token, ex );
            return ValidationResult.failure( ex.getMessage() );
        }
        */
    }
}
