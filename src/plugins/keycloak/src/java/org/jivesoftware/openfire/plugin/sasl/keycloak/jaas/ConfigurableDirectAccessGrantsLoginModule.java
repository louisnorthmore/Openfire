package org.jivesoftware.openfire.plugin.sasl.keycloak.jaas;

import org.jivesoftware.util.JiveGlobals;
import org.keycloak.adapters.KeycloakDeploymentBuilder;
import org.keycloak.adapters.jaas.DirectAccessGrantsLoginModule;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import java.util.HashMap;
import java.util.Map;

/**
 * An extension of org.keycloak.adapters.jaas.DirectAccessGrantsLoginModule that can be configured dynamically, rather than
 * through a static config file.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class ConfigurableDirectAccessGrantsLoginModule extends DirectAccessGrantsLoginModule
{
    private static final Logger Log = LoggerFactory.getLogger( ConfigurableDirectAccessGrantsLoginModule.class );

    @Override
    public void initialize( Subject subject, CallbackHandler callbackHandler, Map<String, ?> sharedState, Map<String, ?> options )
    {
        super.initialize( subject, callbackHandler, sharedState, options );

        if ( deployment != null )
        {
            Log.debug( "A static config file was used to configure the Keycloak interaction. Openfire properties are ignored." );
        }
        else
        {
            Log.trace( "Configuring the Keycloak interaction with Openfire properties." );
            final AdapterConfig adapterConfig = new AdapterConfig();
            adapterConfig.setRealm(         JiveGlobals.getProperty( "keycloak.realm",       "amisnuage" ) );
            adapterConfig.setRealmKey(      JiveGlobals.getProperty( "keycloak.realmKey",    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmb+JWO3+FBh3CvTThSshza0Y0pym8P3ZanCRoFGqYoOZ9FKpyBjweNsz9u30I7G3k6CjZcTh1fvLqOlIqNl3oFmJrdeRRcPeXgtLs+W9EePieSiuLjDa/4b2UxyWaCKcpAPTJt3w61Xe0pq+rA5X4+YUosIjCXMs1ENup5tppVhvZVL5MnCV2I/iYFE5nFl8I+PK6+UhgYvNCCEpTOsxwDCN/7TOTJYWJXNdCt1AHg2YhsbWJI90FxB0hrQk1RPAEIpJ8x6DTLii/5iS0JnbJoLPsfXKfn2u3M9cJkaNII94cY25Xjdhuf9yeqZ7qPsBdKf+jOUBgzGJOnKxLyjFVwIDAQAB" ) );
            adapterConfig.setResource(      JiveGlobals.getProperty( "keycloak.clientId",    "openfire" ) );
            adapterConfig.setAuthServerUrl( JiveGlobals.getProperty( "keycloak.url",         "http://localhost:8080/auth" ) );
            adapterConfig.setSslRequired(   JiveGlobals.getProperty( "keycloak.sslRequired", "external" ) );

            final Map<String, Object> credentials = new HashMap<>();
            credentials.put( "secret", JiveGlobals.getProperty( "keycloak.clientSecret", "6817c4a7-7cbb-4fe1-9182-cf61b28f71ed" ) );
            adapterConfig.setCredentials( credentials );

            deployment = KeycloakDeploymentBuilder.build( adapterConfig );
        }
    }
}
