package org.jivesoftware.openfire.plugin.sasl;

import java.security.Provider;

/**
 * A Provider implementation for OAuth-based SASL mechanisms, as specified by RFC 7628: "A Set of Simple Authentication
 * and Security Layer (SASL) Mechanisms for OAuth"
 *
 * This implementation makes use of a WSO2 Identity Server for token validation.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7628">RFC 7628</a>
 */
public class WSO2ISOAuthSaslProvider extends Provider
{
    /**
     * The provider name.
     */
    public static final String NAME = "WSO2ISOAuthSasl";

    /**
     * The provider version number.
     */
    public static final double VERSION = 1.0;

    /**
     * A description of the provider and its services.
     */
    public static final String INFO = "WSO2 Identity Server backed OAuth-based SASL mechanisms as specified by RFC 7628: \"A Set of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth\"";

    public WSO2ISOAuthSaslProvider()
    {
        super( NAME, VERSION, INFO );

        put( "SaslServerFactory." + WSO2ISOAuthBearerSaslServer.MECHANISM_NAME, WSO2ISOAuthSaslServerFactory.class.getCanonicalName() );
    }
}
