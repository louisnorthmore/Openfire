package org.jivesoftware.openfire.plugin;

import java.io.File;
import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class WSO2ISTesterPlugin implements Plugin  {

    private static final Logger Log = LoggerFactory.getLogger(WSO2ISTesterPlugin.class);

    @Override
    public void initializePlugin(final PluginManager manager, final File pluginDirectory)
    {
    }

    @Override
    public void destroyPlugin()
    {
    }
}
