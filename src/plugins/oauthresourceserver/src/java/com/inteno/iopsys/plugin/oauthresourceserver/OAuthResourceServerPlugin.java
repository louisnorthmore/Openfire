package com.inteno.iopsys.plugin.oauthresourceserver;

import org.jivesoftware.admin.AuthCheckFilter;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;

/**
 * Openfire plugin that instantiates an OAuth Resource Server.
 *
 * The Resource Server will allow clients to obtain bits of information, as long
 * as they provide a valid (OAUTH) access token.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class OAuthResourceServerPlugin implements Plugin
{
    private final static Logger Log = LoggerFactory.getLogger( OAuthResourceServerPlugin.class );

    @Override
    public void initializePlugin( PluginManager manager, File pluginDirectory )
    {
        Log.debug( "Initializing plugin..." );
        AuthCheckFilter.addExclude( "oauthresourceserver/keycloak/*" );
        AuthCheckFilter.addExclude( "oauthresourceserver/protected/*" );
    }

    @Override
    public void destroyPlugin()
    {
        Log.debug( "Destroying plugin..." );
        AuthCheckFilter.removeExclude( "oauthresourceserver/keycloak/*" );
        AuthCheckFilter.removeExclude( "oauthresourceserver/protected/*" );
    }
}
