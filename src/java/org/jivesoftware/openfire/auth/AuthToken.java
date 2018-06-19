/*
 * Copyright (C) 2004-2008 Jive Software. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jivesoftware.openfire.auth;

import org.jivesoftware.openfire.XMPPServerInfo;
import org.jivesoftware.openfire.session.ConnectionSettings;
import org.jivesoftware.util.JiveGlobals;

import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * A token that proves that a user has successfully authenticated.
 *
 * @author Matt Tucker
 * @see AuthFactory
 */
public class AuthToken {

    private static final long serialVersionUID = 2L;
    private final String username;

    /**
     * Constructs a new AuthToken that represents an authenticated user identified by
     * the provider username.
     *
     * @param username the username to create an authToken token with.
     */
    public static AuthToken generateUserToken( String username )
    {
        if ( username == null || username.isEmpty() ) {
            throw new IllegalArgumentException( "Argument 'username' cannot be null." );
        }
        return new AuthToken( username );
    }

    /**
     * Constructs a new AuthToken that represents an authenticated, but anonymous user.
     */
    public static AuthToken generateAnonymousToken()
    {
        return new AuthToken( null );
    }

    /**
     * Constucts a new AuthToken with the specified username.
     * The username can be either a simple username or a full JID.
     *
     * @param jid the username or bare JID to create an authToken token with.
     * @deprecated replaced by {@link #generateUserToken(String)}
     */
    @Deprecated
    public AuthToken(String jid) {
        if (jid == null) {
            this.username = null;
            return;
        }
        int index = jid.indexOf("@");
        if (index > -1) {
            this.username = jid.substring(0,index);
        } else {
            this.username = jid;
        }
    }

    /**
     * Constucts a new AuthToken with the specified username.
     * The username can be either a simple username or a full JID.
     *
     * @param jid the username or bare JID to create an authToken token with.
     * @deprecated replaced by {@link #generateAnonymousToken()}
     */
    @Deprecated
    public AuthToken(String jid, Boolean anonymous) {
        if (jid == null || (anonymous != null && anonymous) ) {
            this.username = null;
            return;
        }
        int index = jid.indexOf("@");
        if (index > -1) {
            this.username = jid.substring(0,index);
        } else {
            this.username = jid;
        }
    }

    /**
     * Returns the username associated with this AuthToken. A <tt>null</tt> value
     * means that the authenticated user is anonymous.
     *
     * @return the username associated with this AuthToken or null when using an anonymous user.
     */
    public String getUsername() {
        return username;
    }

    /**
     * Returns the domain associated with this AuthToken.
     *
     * @return the domain associated with this AuthToken.
     * @deprecated As Openfire serves only one domain, there's no need for a domain-specific token. Use {@link XMPPServerInfo#getXMPPDomain()} instead.
     */
    @Deprecated
    public String getDomain() {
        return JiveGlobals.getProperty("xmpp.domain");
    }

    /**
     * Returns true if this AuthToken is the Anonymous auth token.
     *
     * @return true if this token is the anonymous AuthToken.
     */
    public boolean isAnonymous() {
        return username == null;
    }

    /**
     * Scope that allows data to be send to another XMPP domain (federation).
     */
    public static final String SCOPE_S2S_SENDDATA = "scope.s2s.senddata";

    /**
     * The scopes that are defined for this token.
     *
     * An empty collection implies that all usage is permitted..
     */
    private final ConcurrentMap<String,Set<String>> scopes = new ConcurrentHashMap<>();

    /**
     * Verifies if a scope, without any restrictions to certain details, is
     * allowable for this token.
     *
     * @param scope The scope (cannot be null or empty).
     * @return true if usage is allowed, false otherwise.
     */
    public boolean isAllowed( String scope )
    {
        return isAllowed( scope, null );
    }

    /**
     * Verifies if a scope, optionally restricted to a certain detail, is
     * allowable for this token.
     *
     * @param scope The scope (cannot be null or empty).
     * @param restriction optional restriction detail (can be null, cannot be empty).
     * @return true if usage is allowed, false otherwise.
     */
    public boolean isAllowed( String scope, String restriction )
    {
        if ( scope == null || scope.isEmpty() ) {
            throw new IllegalArgumentException( "Argument 'scope' cannot be null or an empty String." );
        }

        if ( restriction != null && restriction.isEmpty() ) {
            throw new IllegalArgumentException( "Argument 'restriction' cannot be an empty String." );
        }

        // Special, system wide scope definition take priority when they deny usage.
        if ( !isAllowedBySystemConfig( scope, restriction ) ) {
            return false;
        }

        // When no scopes are defined, everything is allowed.
        if ( scopes.isEmpty() ) {
            return true;
        }

        // If there are scopes for this token, but not the scope that is requested, usage is prohibited.
        if ( !scopes.containsKey( scope ) ) {
            return false;
        }

        // A scope is potentially restricted. Check these restrictions.
        final Set<String> restrictions = scopes.get( scope );

        // When there are no restrictions, usage is allowed.
        if ( restrictions == null || restrictions.isEmpty() ) {
            return true;
        }

        // When restrictions are defined, but a restriction is not provided in the request, disallow usage.
        if ( restriction == null ) {
            return false;
        }

        // Allow usage only if the requested restriction is in the defined restrictions.
        return restrictions.contains( restriction );
    }

    /**
     * Verify any system-wide setting.
     *
     * @param scope The scope (cannot be null or empty).
     * @param restriction optional restriction detail (can be null, cannot be empty).
     * @return true if usage is allowed, false otherwise.
     */
    private boolean isAllowedBySystemConfig( String scope, String restriction )
    {
        if ( scope == null || scope.isEmpty() ) {
            throw new IllegalArgumentException( "Argument 'scope' cannot be null or an empty String." );
        }

        if ( restriction != null && restriction.isEmpty() ) {
            throw new IllegalArgumentException( "Argument 'restriction' cannot be an empty String." );
        }

        if ( SCOPE_S2S_SENDDATA.equals( scope ) )
        {
            // Check the system property that controls if anonymous users can send data over federation.
            if ( isAnonymous() && !JiveGlobals.getBooleanProperty( ConnectionSettings.Server.ALLOW_ANONYMOUS_OUTBOUND_DATA, false ) )
            {
                return false;
            }
        }

        return true;
    }
}
