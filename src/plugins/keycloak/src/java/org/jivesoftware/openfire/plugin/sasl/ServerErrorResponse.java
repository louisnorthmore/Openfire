package org.jivesoftware.openfire.plugin.sasl;

import java.net.URL;

/**
 * Created by guus on 9-2-16.
 */
public class ServerErrorResponse
{
    private final String status;
    private final String scope;
    private final URL openidConfiguration;

    public ServerErrorResponse( String status ) {
        this( status, null, null );
    }

    public ServerErrorResponse( String status, String scope, URL openidConfiguration )
    {
        if ( status == null || status.isEmpty() ) {
            throw new IllegalArgumentException( "Argument 'status' cannot be null or empty." );
        }
        this.status = status;
        this.scope = scope;
        this.openidConfiguration = openidConfiguration;
    }

    public String getStatus()
    {
        return status;
    }

    public String getScope()
    {
        return scope;
    }

    public URL getOpenidConfiguration()
    {
        return openidConfiguration;
    }

    public String toJson()
    {
        String json = "{\"status\":\""+status+"\"";

        if ( scope != null && !scope.isEmpty() )
        {
            json += ",\"scope\":\""+scope+"\"";
        }

        if ( openidConfiguration != null )
        {
            json += ",\"openid-configuration\":\""+openidConfiguration.toExternalForm()+"\"";
        }
        json += "}";

        return json;
    }

    @Override
    public boolean equals( Object o )
    {
        if ( this == o )
        {
            return true;
        }
        if ( !( o instanceof ServerErrorResponse ) )
        {
            return false;
        }

        ServerErrorResponse that = (ServerErrorResponse) o;

        if ( !status.equals( that.status ) )
        {
            return false;
        }
        if ( scope != null ? !scope.equals( that.scope ) : that.scope != null )
        {
            return false;
        }
        return !( openidConfiguration != null ? !openidConfiguration.equals( that.openidConfiguration ) : that.openidConfiguration != null );

    }

    @Override
    public int hashCode()
    {
        int result = status.hashCode();
        result = 31 * result + ( scope != null ? scope.hashCode() : 0 );
        result = 31 * result + ( openidConfiguration != null ? openidConfiguration.hashCode() : 0 );
        return result;
    }

    @Override
    public String toString()
    {
        return "ServerErrorResponse{" +
                "status='" + status + '\'' +
                ", scope='" + scope + '\'' +
                ", openidConfiguration=" + openidConfiguration +
                '}';
    }
}
