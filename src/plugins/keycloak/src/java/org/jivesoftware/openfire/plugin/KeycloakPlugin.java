package org.jivesoftware.openfire.plugin;

import java.io.File;
import java.security.Security;

import org.jivesoftware.openfire.auth.AuthFactory;
import org.jivesoftware.openfire.auth.AuthProvider;
import org.jivesoftware.openfire.auth.AuthorizationManager;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.group.GroupManager;
import org.jivesoftware.openfire.group.GroupProvider;
import org.jivesoftware.openfire.net.SASLAuthentication;
import org.jivesoftware.openfire.plugin.sasl.OAuthBearerSaslServer;
import org.jivesoftware.openfire.plugin.sasl.keycloak.KeycloakOAuthSaslProvider;
import org.jivesoftware.openfire.plugin.sasl.keycloak.jaas.KeycloakJaasConfiguration;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserProvider;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.login.Configuration;

public class KeycloakPlugin implements Plugin  {

    private static final Logger Log = LoggerFactory.getLogger(KeycloakPlugin.class);

    // Backup to restore when we're unloading this plugin.
    private String oldAuthProvider = null;
    private String oldUserProvider = null;
    private String oldGroupProvider = null;

    @Override
    public void initializePlugin(final PluginManager manager, final File pluginDirectory)
    {
        loadKeycloakAuthProvider();
        loadKeycloakUserProvider();
        loadKeycloakGroupProvider();
        loadKeycloakAuthentication();
    }

    @Override
    public void destroyPlugin()
    {
        revertToPreviousGroupProvider();
        revertToPreviousUserProvider();
        revertToPreviousAuthProvider();
        removeKeycloakAuthentication();
    }

    /**
     * Loads or reloads a Keycloak-backed auth provider.
     */
    protected void loadKeycloakAuthProvider()
    {
        Log.debug( "... adding Keycloak-based auth provider..." );
        oldAuthProvider = JiveGlobals.getProperty( "provider.auth.className" );
        try
        {
            if ( KeycloakAuthProvider.class.getCanonicalName().equals( oldAuthProvider ) )
            {
                Log.warn( "Keycloak auth provider configuration was present before it was loaded. Unloading (to reload later)." );
                // There appears to be a lingering provider. This might be a result of a previous failure, or an unclean
                // shutdown of Openfire. As this plugin is supplying the provider, the old one is probably faulty.
                // Unload and reload.
                revertToPreviousAuthProvider();
            }
            JiveGlobals.setProperty( "provider.auth.className", KeycloakAuthProvider.class.getCanonicalName() );

            // Check to see if the provider was loaded successfully. If not, fall back.
            if ( !( AuthFactory.getAuthProvider() instanceof KeycloakAuthProvider ) )
            {
                Log.error( "The Keycloak auth provider was not loaded (warnings will have been logged immediately preceding this log statement). Falling back to the previous provider." );
                revertToPreviousAuthProvider();
            }
        }
        catch ( Exception ex )
        {
            Log.error( "An exception occurred while tyring to initialize the Keycloak auth provider!", ex );
            // Restore the old provider if the new one won't work.
            revertToPreviousAuthProvider();
        }
    }

    /**
     * Restores the auth provider that was loaded before the keycloak provider was loaded.
     */
    protected void revertToPreviousAuthProvider()
    {
        Log.trace( "Reverting to previous Auth provider..." );
        final AuthProvider authProvider = AuthFactory.getAuthProvider();
        if ( authProvider instanceof KeycloakAuthProvider )
        {
            Log.debug( "Disposing of the currently loaded Keycloak auth provider..." );
            try
            {
                ((KeycloakAuthProvider) authProvider).dispose();
            }
            catch ( Exception ex )
            {
                Log.warn( "An exception occurred while tyring to dispose of the Keycloak auth provider!", ex );
            }
        }

        if ( oldAuthProvider != null && !oldAuthProvider.equals( KeycloakAuthProvider.class.getCanonicalName() ))
        {
            Log.debug( "Restoring the '{}' auth provider...", oldAuthProvider );
            JiveGlobals.setProperty( "provider.auth.className", oldAuthProvider );
            oldAuthProvider = null;
        }
        else
        {
            Log.debug( "Restoring the default auth provider..." );
            JiveGlobals.deleteProperty( "provider.auth.className" );
        }
        Log.debug( "Reverted to the previous auth provider." );
    }

    /**
     * Loads or reloads a Keycloak-backed user provider.
     */
    protected void loadKeycloakUserProvider()
    {
        Log.debug( "... adding Keycloak-based user provider..." );
        oldUserProvider = JiveGlobals.getProperty( "provider.user.className" );
        try
        {
            if ( KeycloakUserProvider.class.getCanonicalName().equals( oldUserProvider ) )
            {
                Log.warn( "Keycloak user provider configuration was present before it was loaded. Unloading (to reload later)." );
                // There appears to be a lingering provider. This might be a result of a previous failure, or an unclean
                // shutdown of Openfire. As this plugin is supplying the provider, the old one is probably faulty.
                // Unload and reload.
                revertToPreviousUserProvider();
            }
            JiveGlobals.setProperty( "provider.user.className", KeycloakUserProvider.class.getCanonicalName() );

            // Check to see if the provider was loaded successfully. If not, fall back.
            if ( !(UserManager.getUserProvider() instanceof KeycloakUserProvider ) )
            {
                Log.error( "The Keycloak user provider was not loaded (warnings will have been logged immediately preceding this log statement). Falling back to the previous provider." );
                revertToPreviousUserProvider();
            }
        }
        catch ( Exception ex )
        {
            Log.error( "An exception occurred while tyring to initialize the Keycloak user provider!", ex );
            // Restore the old provider if the new one won't work.
            revertToPreviousUserProvider();
        }
    }

    /**
     * Restores the user provider that was loaded before the keycloak provider was loaded.
     */
    protected void revertToPreviousUserProvider()
    {
        Log.trace( "Reverting to previous user provider..." );
        final UserProvider userProvider = UserManager.getUserProvider();
        if ( userProvider instanceof KeycloakUserProvider )
        {
            Log.debug( "Disposing of the currently loaded Keycloak user provider..." );
            try
            {
                ((KeycloakUserProvider) userProvider).dispose();
            }
            catch ( Exception ex )
            {
                Log.warn( "An exception occurred while tyring to dispose of the Keycloak user provider!", ex );
            }
        }

        if ( oldUserProvider != null && !oldUserProvider.equals( KeycloakUserProvider.class.getCanonicalName() ))
        {
            Log.debug( "Restoring the '{}' user provider...", oldUserProvider );
            JiveGlobals.setProperty( "provider.user.className", oldUserProvider );
            oldUserProvider = null;
        }
        else
        {
            Log.debug( "Restoring the default user provider..." );
            JiveGlobals.deleteProperty( "provider.user.className" );
        }
        Log.debug( "Reverted to the previous user provider." );
    }

    /**
     * Loads or reloads a Keycloak-backed group provider.
     */
    protected void loadKeycloakGroupProvider()
    {
        Log.debug( "... adding Keycloak-based group provider..." );
        oldGroupProvider = JiveGlobals.getProperty( "provider.group.className" );
        try
        {
            if ( KeycloakGroupProvider.class.getCanonicalName().equals( oldGroupProvider ) )
            {
                Log.warn( "Keycloak group provider configuration was present before it was loaded. Unloading (to reload later)." );
                // There appears to be a lingering provider. This might be a result of a previous failure, or an unclean
                // shutdown of Openfire. As this plugin is supplying the provider, the old one is probably faulty.
                // Unload and reload.
                revertToPreviousGroupProvider();
            }
            JiveGlobals.setProperty( "provider.group.className", KeycloakGroupProvider.class.getCanonicalName() );

            // Check to see if the provider was loaded successfully. If not, fall back.
            if ( !(GroupManager.getInstance().getProvider() instanceof KeycloakGroupProvider ) )
            {
                Log.error( "The Keycloak group provider was not loaded (warnings will have been logged immediately preceding this log statement). Falling back to the previous provider." );
                revertToPreviousGroupProvider();
            }
        }
        catch ( Exception ex )
        {
            Log.error( "An exception occurred while tyring to initialize the Keycloak group provider!", ex );
            // Restore the old provider if the new one won't work.
            revertToPreviousGroupProvider();
        }
    }

    /**
     * Restores the group provider that was loaded before the keycloak provider was loaded.
     */
    protected void revertToPreviousGroupProvider()
    {
        Log.trace( "Reverting to previous group provider..." );
        final GroupProvider groupProvider = GroupManager.getInstance().getProvider();
        if ( groupProvider instanceof KeycloakGroupProvider )
        {
            Log.debug( "Disposing of the currently loaded Keycloak group provider..." );
            try
            {
                ((KeycloakGroupProvider) groupProvider).dispose();
            }
            catch ( Exception ex )
            {
                Log.warn( "An exception occurred while tyring to dispose of the Keycloak group provider!", ex );
            }
        }

        if ( oldGroupProvider != null && !oldGroupProvider.equals( KeycloakGroupProvider.class.getCanonicalName() ))
        {
            Log.debug( "Restoring the '{}' group provider...", oldGroupProvider );
            JiveGlobals.setProperty( "provider.group.className", oldGroupProvider );
            oldGroupProvider = null;
        }
        else
        {
            Log.debug( "Restoring the default group provider..." );
            JiveGlobals.deleteProperty( "provider.group.className" );
        }
        Log.debug( "Reverted to the previous group provider." );
    }

    private void loadKeycloakAuthentication()
    {
        // Keycloak JAAS configuration, to allow for dynamic configuration of the login manager (without config files).
        // What's potentially nasty here is that one static configuration is re-used everywhere. This probably does not
        // play well with other code that does JAAS.
        Configuration.setConfiguration( new KeycloakJaasConfiguration() );

        Log.debug( "... adding Keycloak-based authentication mechanisms (OAUTH Bearer)..." );
        Security.addProvider( new KeycloakOAuthSaslProvider() );
        SASLAuthentication.addSupportedMechanism( OAuthBearerSaslServer.MECHANISM_NAME );
    }

    private void removeKeycloakAuthentication()
    {
        Log.debug( "... removing Keycloak-based authentication mechanisms (OAUTH Bearer)..." );
        SASLAuthentication.removeSupportedMechanism( OAuthBearerSaslServer.MECHANISM_NAME );
        Security.removeProvider( KeycloakOAuthSaslProvider.NAME );

        // Revert JAAS configuration to the default JVM setting.
        Configuration.setConfiguration( null );
    }
}
