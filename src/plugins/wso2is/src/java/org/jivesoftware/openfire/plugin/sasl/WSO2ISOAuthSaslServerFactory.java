package org.jivesoftware.openfire.plugin.sasl;

import javax.security.auth.callback.CallbackHandler;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import javax.security.sasl.SaslServer;
import javax.security.sasl.SaslServerFactory;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * A SaslServerFactory implementation that is used to instantiate OAuth-based SaslServer instances, as specified by
 * RFC 7628: "A Set of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth"
 *
 * This implementation makes use of a WSO2 Identity Server for token validation.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 * @see <a href="https://tools.ietf.org/html/rfc7628">RFC 7628</a>
 */
public class WSO2ISOAuthSaslServerFactory implements SaslServerFactory
{
    public WSO2ISOAuthSaslServerFactory()
    {
        // The interface requires that a no-argument constructor is present.
    }

    public SaslServer createSaslServer( String mechanism, String protocol, String serverName, Map<String, ?> props, CallbackHandler cbh ) throws SaslException
    {
        // Do not return an instance when the provided properties contain Policy settings that disallow our implementations.
        final Set<String> mechanismNames = getMechanismNamesSet( props );

        if ( mechanismNames.contains( mechanism ) && mechanism.equalsIgnoreCase( WSO2ISOAuthBearerSaslServer.MECHANISM_NAME ) )
        {
            return new WSO2ISOAuthBearerSaslServer();
        }

        return null;
    }

    public String[] getMechanismNames( Map<String, ?> props )
    {
        final Set<String> result = getMechanismNamesSet( props );
        return result.toArray( new String[ result.size() ] );
    }

    protected final Set<String> getMechanismNamesSet( Map<String, ?> props )
    {
        final Set<String> supportedMechanisms = new HashSet<String>();
        supportedMechanisms.add( WSO2ISOAuthBearerSaslServer.MECHANISM_NAME );

        if ( props != null )
        {
            for ( Map.Entry<String, ?> prop : props.entrySet() )
            {
                if ( !( prop.getValue() instanceof String ) )
                {
                    continue;
                }

                final String name = prop.getKey();
                final String value = (String) prop.getValue();

                if ( Sasl.POLICY_NOPLAINTEXT.equalsIgnoreCase( name ) && "true".equalsIgnoreCase( value ) )
                {
                    supportedMechanisms.remove( WSO2ISOAuthBearerSaslServer.MECHANISM_NAME );
                }

                // TODO Determine if other policies are relevant.
            }
        }
        return supportedMechanisms;
    }
}
