package org.jivesoftware.openfire.plugin;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.group.AbstractGroupProvider;
import org.jivesoftware.openfire.group.Group;
import org.jivesoftware.openfire.group.GroupNotFoundException;
import org.jivesoftware.openfire.plugin.keycloak.Keycloak;
import org.jivesoftware.util.JiveGlobals;
import org.keycloak.admin.client.resource.*;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import java.util.*;

/**
 * A group provider that is backed by a Keycloak instance.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class KeycloakGroupProvider extends AbstractGroupProvider
{
    private final static Logger Log = LoggerFactory.getLogger( KeycloakGroupProvider.class );

    private Keycloak keycloak = null;
    private RealmResource realmResource;
    private GroupsResource groupsResource;
    private UsersResource usersResource;
    private String xmppDomain;

    public KeycloakGroupProvider()
    {
        initialize();
    }

    public synchronized void dispose()
    {
        if ( keycloak != null )
        {
            try
            {
                keycloak.close();
            }
            finally
            {
                keycloak = null;
            }
        }

        realmResource = null;
        groupsResource = null;
        usersResource = null;
        xmppDomain = null;
    }

    private synchronized void initialize()
    {
        dispose();

        xmppDomain = XMPPServer.getInstance().getServerInfo().getXMPPDomain();

        final String serverUrl = JiveGlobals.getProperty( "keycloak.url", "http://localhost:8080/auth" );
        final String realm = JiveGlobals.getProperty( "keycloak.realm", "amisnuage" );
        final String username = JiveGlobals.getProperty( "keycloak.username", "admin" );
        final String password = JiveGlobals.getProperty( "keycloak.password", "admin" );
        final String clientId = JiveGlobals.getProperty( "keycloak.clientId", "openfire" );
        final String clientSecret = JiveGlobals.getProperty( "keycloak.clientSecret", "6817c4a7-7cbb-4fe1-9182-cf61b28f71ed" );

        keycloak = Keycloak.getInstance(serverUrl, realm, username, password, clientId, clientSecret );
        realmResource = keycloak.realm( realm );
        groupsResource = keycloak.realm( realm ).groups();
        usersResource = keycloak.realm( realm ).users();

        // Verify that communication with the keycloak server is possible.
        groupsResource.group( "test" );
        usersResource.search( "test", null, null, null, 0, 1 );
    }

    @Override
    public Group getGroup( String name ) throws GroupNotFoundException
    {
        final GroupRepresentation groupRepresentation = realmResource.getGroupByPath( "/" + name );
        if (groupRepresentation == null ) {
            throw new GroupNotFoundException();
        }

        final GroupResource keycloakGroup = groupsResource.group( groupRepresentation.getId() );
        if (keycloakGroup == null ) {
            throw new GroupNotFoundException();
        }

        final String description = null;

        final String adminRole = JiveGlobals.getProperty( "keycloak.adminrole", "realm-admin" );
        final Set<JID> members = new HashSet<>();
        final Set<JID> admins = new HashSet<>();

        final List<UserRepresentation> memberRepresentations = keycloakGroup.members( 0, Integer.MAX_VALUE );
        for ( UserRepresentation member : memberRepresentations ) {
            // Note that this assumes that every user in the group is a member of the local domain.
            final JID jid = new JID( member.getUsername(), xmppDomain, null );

            if ( member.getRealmRoles() != null && member.getRealmRoles().contains( adminRole ) )
            {
                admins.add( jid );
            }
            else
            {
                members.add( jid );
            }
        }

        final Group openfireGroup = new Group( name, description, members, admins );

        return openfireGroup;
    }

    @Override
    public int getGroupCount()
    {
        return groupsResource.groups().size();
    }

    @Override
    public Collection<String> getGroupNames()
    {
        return getGroupNames( 0, Integer.MAX_VALUE );
    }

    @Override
    public Collection<String> getGroupNames( int startIndex, int numResults )
    {
        final List<String> result = new ArrayList<>();
        for ( GroupRepresentation groupRepresentation : groupsResource.groups() )
        {
            result.add( groupRepresentation.getName() );
        }
        return Collections.unmodifiableList( result.subList( startIndex, numResults > result.size() ? result.size() : numResults ) );
    }

    @Override
    public Collection<String> getGroupNames( JID user )
    {
//        final List<UserRepresentation> userRepresentations = usersResource.search( user.getNode(), null, null, null, 0, Integer.MAX_VALUE );
//        for ( UserRepresentation userRepresentation : userRepresentations ) {
//            if (userRepresentation.getUsername().equals(user.getNode())) { // assumes that the first exact username hit is correct (and thus unique).
//                return userRepresentation.getGroups() != null ? userRepresentation.getGroups() : Collections.<String>emptyList();
//            }
//        }
//
//        return Collections.emptyList();

        final Set<String> result = new HashSet<>();
        final List<UserRepresentation> userRepresentations = usersResource.search( user.getNode(), null, null, null, 0, Integer.MAX_VALUE );
        for ( UserRepresentation userRepresentation : userRepresentations ) {
            if (userRepresentation.getUsername().equals(user.getNode())) { // assumes usernames are unique.
                final List<GroupRepresentation> groups = usersResource.get( userRepresentation.getId() ).groups();
                for ( GroupRepresentation group : groups )
                {
                    result.add( group.getName() );
                }
            }
        }

        return Collections.unmodifiableSet( result );
    }
}
