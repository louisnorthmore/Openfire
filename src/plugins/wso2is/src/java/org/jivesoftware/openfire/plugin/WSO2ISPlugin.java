package org.jivesoftware.openfire.plugin;

import java.io.File;
import java.security.Security;

import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.net.SASLAuthentication;
import org.jivesoftware.openfire.plugin.sasl.WSO2ISOAuthBearerSaslServer;
import org.jivesoftware.openfire.plugin.sasl.WSO2ISOAuthSaslProvider;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserProvider;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WSO2ISPlugin implements Plugin  {

    private static final Logger Log = LoggerFactory.getLogger(WSO2ISPlugin.class);

    // Backup to restore when we're unloading this plugin.
    private String oldUserProvider = null;

    @Override
    public void initializePlugin(final PluginManager manager, final File pluginDirectory)
    {
        Log.debug( "Loading plugin..." );

        // WSO2IS communication over TLS requires a custom trust store. I have not figured out a way to configure in another
        // way than with (very global) system properties. If we can somehow apply this to wso2/axis specifically, that'd be better.
        System.setProperty( "javax.net.ssl.trustStore", "/home/guus/Downloads/wso2is-5.1.0/repository/resources/security/wso2carbon.jks" );
        System.setProperty( "javax.net.ssl.trustStorePassword", "wso2carbon" );
        System.setProperty( "javax.net.ssl.trustStoreType", "JKS" );

        Log.debug( "... adding WSO2IS-based authentication mechanisms (OAUTH Bearer)..." );
        Security.addProvider( new WSO2ISOAuthSaslProvider() );
        SASLAuthentication.addSupportedMechanism( WSO2ISOAuthBearerSaslServer.MECHANISM_NAME );

        Log.debug( "... adding WSO2IS-based user provider..." );
        oldUserProvider = JiveGlobals.getProperty( "provider.user.className" );
        JiveGlobals.setProperty( "provider.user.className", WSO2UserProvider.class.getCanonicalName() );
        final WSO2UserProvider userProvider = (WSO2UserProvider) UserManager.getUserProvider();
        try
        {
            userProvider.initialize();
            Log.info( "Plugin loaded." );
        }
        catch ( Exception ex )
        {
            Log.error( "An exception occurred while tyring to initialize the WSO2IS user provider!", ex );
            destroyPlugin();
        }

    }

    @Override
    public void destroyPlugin()
    {
        Log.debug( "Destroying plugin..." );

        final UserProvider userProvider = UserManager.getUserProvider();
        if ( userProvider instanceof WSO2UserProvider )
        {
            Log.debug( "... removing WSO2IS-based user provider..." );
            try
            {
                ((WSO2UserProvider) userProvider).dispose();
            }
            catch ( Exception ex )
            {
                Log.error( "An exception occurred while tyring to dispose the WSO2IS user provider!", ex );
            }
            finally
            {
                if ( oldUserProvider != null )
                {
                    JiveGlobals.setProperty( "provider.user.className", oldUserProvider );
                }
                else
                {
                    JiveGlobals.deleteProperty( "provider.user.className" );
                }
            }
        }

        Log.debug( "... removing WSO2IS-based authentication mechanisms (OAUTH Bearer)..." );
        SASLAuthentication.removeSupportedMechanism( WSO2ISOAuthBearerSaslServer.MECHANISM_NAME );
        Security.removeProvider( WSO2ISOAuthSaslProvider.NAME );

        Log.info( "Plugin destroyed." );
    }
}
