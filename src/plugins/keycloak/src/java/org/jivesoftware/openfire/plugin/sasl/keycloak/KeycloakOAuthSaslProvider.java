package org.jivesoftware.openfire.plugin.sasl.keycloak;

import org.jivesoftware.openfire.plugin.sasl.OAuthBearerSaslServer;

import javax.security.auth.login.Configuration;
import java.security.Provider;

/**
 * A Provider implementation for OAuth-based SASL mechanisms, as specified by RFC 7628: "A Set of Simple Authentication
 * and Security Layer (SASL) Mechanisms for OAuth"
 *
 * This implementation makes use of a Keycloak server for token validation.
 *
 * @see <a href="https://tools.ietf.org/html/rfc7628">RFC 7628</a>
 */
public class KeycloakOAuthSaslProvider extends Provider
{
    /**
     * The provider name.
     */
    public static final String NAME = "KeycloakOAuthSasl";

    /**
     * The provider version number.
     */
    public static final double VERSION = 1.0;

    /**
     * A description of the provider and its services.
     */
    public static final String INFO = "Keycloak backed OAuth-based SASL mechanisms as specified by RFC 7628: \"A Set of Simple Authentication and Security Layer (SASL) Mechanisms for OAuth\"";

    public KeycloakOAuthSaslProvider()
    {
        super( NAME, VERSION, INFO );

        put( "SaslServerFactory." + OAuthBearerSaslServer.MECHANISM_NAME, KeycloakOAuthSaslServerFactory.class.getCanonicalName() );
    }
}