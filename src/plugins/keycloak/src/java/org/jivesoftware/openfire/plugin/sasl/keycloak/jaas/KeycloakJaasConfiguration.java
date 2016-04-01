package org.jivesoftware.openfire.plugin.sasl.keycloak.jaas;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import java.util.Collections;

/**
 * A JAAS Configuration object that ensures that the Keycloak login module is used.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class KeycloakJaasConfiguration extends Configuration
{
    private static final Logger Log = LoggerFactory.getLogger( KeycloakJaasConfiguration.class );

    public static final String NAME = "KEYCLOAK_JAAS_CONFIGURATION";

    @Override
    public AppConfigurationEntry[] getAppConfigurationEntry( String name )
    {
        if ( ! NAME.equals( name ) ) {
            Log.debug( "Unable to provide configuration for '{}'.", name );
            return null;
        }

        return new AppConfigurationEntry[ ] {
            new AppConfigurationEntry(
                    ConfigurableBearerTokenLoginModule.class.getCanonicalName(),
                    AppConfigurationEntry.LoginModuleControlFlag.REQUIRED,
                    Collections.<String, Object>emptyMap()
            )
        };
    }
}
