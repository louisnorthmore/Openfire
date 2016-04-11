package org.jivesoftware.openfire.plugin;

import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.group.AbstractGroupProvider;
import org.jivesoftware.openfire.group.Group;
import org.jivesoftware.openfire.group.GroupAlreadyExistsException;
import org.jivesoftware.openfire.group.GroupNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.GroupsResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;

import javax.ws.rs.NotFoundException;
import javax.ws.rs.core.Response;
import java.util.*;

/**
 * A group provider that is backed by a Keycloak instance.
 *
 * Keycloak does not provide annotated group membership, but does have group metadata. This class uses one of those
 * metadata fields to store all group admins. This is facilitated by the #markAsAdmin and #unmarkAsAdmin methods.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
// TODO Make it possible to add JIDs that do not belong to the local XMPP domain to a group!
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

        keycloak = Keycloak.getInstance( serverUrl, realm, username, password, clientId, clientSecret );
        realmResource = keycloak.realm( realm );
        groupsResource = keycloak.realm( realm ).groups();
        usersResource = keycloak.realm( realm ).users();

        // Verify that communication with the keycloak server is possible.
        groupsResource.group( "test" );
        usersResource.search( "test", null, null, null, 0, 1 );
    }

    @Override
    public Group createGroup( String name )
    {
        Response response = null;
        try
        {
            // Create group.
            final GroupRepresentation representation = new GroupRepresentation();
            representation.setName( name );
            response = groupsResource.add( representation );
            if ( response.getStatus() == Response.Status.CONFLICT.getStatusCode() )
            {
                // TODO this is a bug (OF-1126) in Openfire: the interface defines that the method throws GroupAlreadyExistsException, but the abstract implementation that we're extending from hides this. throw new GroupAlreadyExistsException();
                throw new IllegalStateException( "Group already exists:" + name );
            }
        }
        finally
        {
            if ( response != null )
            {
                response.close();
            }
        }

        // Retrieve newly created group.
        try
        {
            return getGroup( name );
        }
        catch ( GroupNotFoundException ex )
        {
            throw new IllegalStateException( "An unexpected problem occurred while attempting to create a group named: " + name, ex );
        }
    }

    @Override
    public void deleteGroup( String name )
    {
        try
        {
            final GroupRepresentation representation = getGroupRepresentation( name );
            groupsResource.group( representation.getId() ).remove();
        }
        catch ( GroupNotFoundException e )
        {
            Log.info( "Silently ignoring a request to delete a group that does not exist in the first place. Group name: '{}'.", name );
        }
    }

    protected GroupRepresentation getGroupRepresentation( String name ) throws GroupNotFoundException
    {
        try
        {
            final GroupRepresentation groupRepresentation = realmResource.getGroupByPath( "/" + name );
            if ( groupRepresentation == null )
            {
                throw new GroupNotFoundException();
            }
            return groupRepresentation;
        }
        catch ( NotFoundException ex )
        {
            throw new GroupNotFoundException( ex );
        }
    }

    @Override
    public Group getGroup( String name ) throws GroupNotFoundException
    {
        final GroupRepresentation groupRepresentation = getGroupRepresentation( name );

        final GroupResource keycloakGroup = groupsResource.group( groupRepresentation.getId() );
        if ( keycloakGroup == null )
        {
            throw new GroupNotFoundException();
        }

        final String description;
        final String descriptionAttribute = JiveGlobals.getProperty( "keycloak.group.description", "openfire-description" );
        if ( groupRepresentation.getAttributes() != null && groupRepresentation.getAttributes().get( descriptionAttribute ) != null )
        {
            final List<String> strings = groupRepresentation.getAttributes().get( descriptionAttribute );
            final StringBuilder sb = new StringBuilder();
            for ( final String string : strings )
            {
                sb.append( string.trim() );
                sb.append( ' ' );
            }
            description = sb.toString().trim();
        }
        else
        {
            description = null;
        }

        Collection<String> adminIDs = Collections.emptyList();
        if ( groupRepresentation.getAttributes() != null )
        {
            final String attributeName = JiveGlobals.getProperty( "keycloak.group.admins", "group-admins" );
            final List<String> attributeValue = groupRepresentation.getAttributes().get( attributeName );
            if ( attributeValue != null )
            {
                adminIDs = attributeValue;
            }
        }

        final Set<JID> members = new HashSet<>();
        final Set<JID> admins = new HashSet<>();

        final List<UserRepresentation> memberRepresentations = keycloakGroup.members( 0, Integer.MAX_VALUE );
        for ( UserRepresentation member : memberRepresentations )
        {
            // Note that this assumes that every user in the group is a member of the local domain.
            final JID jid = new JID( member.getUsername(), xmppDomain, null );

            if ( adminIDs.contains( member.getId() ) )
            {
                admins.add( jid );
            }
            else
            {
                members.add( jid );
            }
        }

        return new Group( name, description, members, admins );
    }

    @Override
    public void setName( String oldName, String newName ) throws GroupAlreadyExistsException
    {
        // It appears that the REST interface used to apply this change to Keycloak allows for the new group name to
        // be equal to the name of a group that already exists. To avoid duplicate group names, check explicitly here.
        try
        {
            getGroupRepresentation( newName );
            throw new GroupAlreadyExistsException();
        }
        catch ( GroupNotFoundException e )
        {
            // Good: no group already exists with the name that's going to be used.
        }

        try
        {
            final GroupRepresentation oldRepresentation = getGroupRepresentation( oldName );
            oldRepresentation.setName( newName );

            groupsResource.group( oldRepresentation.getId() ).update( oldRepresentation );
        }
        catch ( GroupNotFoundException ex )
        {
            throw new IllegalStateException( "AN unexpected exception occurred while renaming group '" + oldName + "' (to '" + newName + "'): ", ex );
        }
    }

    @Override
    public void setDescription( String name, String description ) throws GroupNotFoundException
    {
        final String descriptionAttribute = JiveGlobals.getProperty( "keycloak.group.description", "openfire-description" );

        final GroupRepresentation representation = getGroupRepresentation( name );

        if ( description == null || description.isEmpty() )
        {
            if ( representation.getAttributes() != null )
            {
                representation.getAttributes().remove( descriptionAttribute );
            }
        }
        else
        {
            representation.singleAttribute( descriptionAttribute, description );
        }
        groupsResource.group( representation.getId() ).update( representation );
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
    public boolean isSharingSupported()
    {
        return false;
    }

    @Override
    public Collection<String> getSharedGroupNames()
    {
        return Collections.emptySet(); // Unsupported.
    }

    @Override
    public Collection<String> getSharedGroupNames( JID user )
    {
        return Collections.emptySet(); // Unsupported.
    }

    @Override
    public Collection<String> getPublicSharedGroupNames()
    {
        return Collections.emptySet(); // Unsupported.
    }

    @Override
    public Collection<String> getVisibleGroupNames( String userGroup )
    {
        return Collections.emptySet(); // Unsupported.
    }

    @Override
    public Collection<String> getGroupNames( int startIndex, int numResults )
    {
        final List<String> result = new ArrayList<>();
        for ( GroupRepresentation groupRepresentation : groupsResource.groups() )
        {
            result.add( groupRepresentation.getName() );
        }
        return Collections.unmodifiableList( result.subList( startIndex, startIndex + numResults > result.size() ? result.size() : numResults ) );
    }

    @Override
    public Collection<String> getGroupNames( JID user )
    {
        final Set<String> result = new HashSet<>();
        final List<UserRepresentation> userRepresentations = usersResource.search( user.getNode(), null, null, null, 0, Integer.MAX_VALUE );
        for ( UserRepresentation userRepresentation : userRepresentations )
        {
            if ( userRepresentation.getUsername().equals( user.getNode() ) ) // assumes usernames are unique.
            {

                final List<GroupRepresentation> groups = usersResource.get( userRepresentation.getId() ).groups();
                for ( GroupRepresentation group : groups )
                {
                    result.add( group.getName() );
                }
            }
        }

        return Collections.unmodifiableSet( result );
    }

    @Override
    public void addMember( String groupName, JID user, boolean administrator )
    {
        try
        {
            // Add user to the group.
            final GroupRepresentation groupRepresentation = getGroupRepresentation( groupName );

            final List<UserRepresentation> userRepresentations = usersResource.search( user.getNode(), null, null, null, 0, Integer.MAX_VALUE );
            for ( UserRepresentation userRepresentation : userRepresentations )
            {
                if ( userRepresentation.getUsername().equals( user.getNode() ) ) // assumes usernames are unique.
                {
                    // Add the user to the group.
                    usersResource.get( userRepresentation.getId() ).joinGroup( groupRepresentation.getId() );

                    // Mark (or unmark, for good measure) the user as an admin for this group.
                    if ( administrator )
                    {
                        markAsAdmin( groupRepresentation, userRepresentation );
                    }
                    else
                    {
                        unmarkAsAdmin( groupRepresentation, userRepresentation );
                    }
                }
            }
        }
        catch ( GroupNotFoundException ex )
        {
            Log.warn( "Silently ignoring an attempt to add user '{}' to non-existing group '{}'.", user, groupName, ex );
        }
    }

    @Override
    public void updateMember( String groupName, JID user, boolean administrator )
    {
        try
        {
            // Add user to the group.
            final GroupRepresentation groupRepresentation = getGroupRepresentation( groupName );

            final List<UserRepresentation> userRepresentations = groupsResource.group( groupRepresentation.getId() ).members( 0, Integer.MAX_VALUE );
            for ( UserRepresentation userRepresentation : userRepresentations )
            {
                if ( userRepresentation.getUsername().equals( user.getNode() ) ) // assumes usernames are unique.
                {
                    // Mark or unmark the user as an admin for this group.
                    if ( administrator )
                    {
                        markAsAdmin( groupRepresentation, userRepresentation );
                    }
                    else
                    {
                        unmarkAsAdmin( groupRepresentation, userRepresentation );
                    }
                }
            }
        }
        catch ( GroupNotFoundException ex )
        {
            Log.warn( "Silently ignoring an attempt to add user '{}' to non-existing group '{}'.", user, groupName, ex );
        }
    }

    @Override
    public void deleteMember( String groupName, JID user )
    {
        try
        {
            // Add user to the group.
            final GroupRepresentation groupRepresentation = getGroupRepresentation( groupName );

            final List<UserRepresentation> userRepresentations = groupsResource.group( groupRepresentation.getId() ).members( 0, Integer.MAX_VALUE );
            for ( UserRepresentation userRepresentation : userRepresentations )
            {
                if ( userRepresentation.getUsername().equals( user.getNode() ) ) // assumes usernames are unique.
                {
                    // Remove the user from the group.
                    usersResource.get( userRepresentation.getId() ).leaveGroup( groupRepresentation.getId() );

                    // Make sure that the group metadata does no longer refer to the user.
                    unmarkAsAdmin( groupRepresentation, userRepresentation );
                }
            }
        }
        catch ( GroupNotFoundException ex )
        {
            Log.warn( "Silently ignoring an attempt to remove user '{}' from non-existing group '{}'.", user, groupName, ex );
        }
    }

    @Override
    public boolean isReadOnly()
    {
        return false;
    }

    @Override
    public Collection<String> search( String query )
    {
        return Collections.emptyList(); // Keycloak does not support group name searches.
    }

    @Override
    public Collection<String> search( String query, int startIndex, int numResults )
    {
        return Collections.emptyList(); // Keycloak does not support group name searches.
    }

    @Override
    public Collection<String> search( String key, String value )
    {
        return Collections.emptyList(); // Keycloak does not support group name searches.
    }

    @Override
    public boolean isSearchSupported()
    {
        return false; // Keycloak does not support group name searches.
    }

    /**
     * Marks a user as an admin of a group.
     *
     * This method makes use of a group metadata attribute, that holds all admins for the group. This method adds an
     * entry to that attribute value.
     *
     * This method modifies only the group metadata - it does not add the user to the group.
     *
     * When the user has already been marked as an admin for the group, no changes are applied.
     *
     * Even when the group is not changed, an invocation of this method will cause an update in keycloak to be executed.
     *
     * @param groupRepresentation The group of which the user should be an admin (cannot be null).
     * @param userRepresentation  The user that is to be an admin of the group (cannot be null).
     */
    protected void markAsAdmin( GroupRepresentation groupRepresentation, UserRepresentation userRepresentation )
    {
        if ( groupRepresentation.getAttributes() == null )
        {
            groupRepresentation.setAttributes( new HashMap<String, List<String>>() );
        }

        final String attributeName = JiveGlobals.getProperty( "keycloak.group.admins", "group-admins" );
        if ( groupRepresentation.getAttributes().get( attributeName ) == null )
        {
            groupRepresentation.getAttributes().put( attributeName, new ArrayList<String>() );
        }

        final List<String> admins = groupRepresentation.getAttributes().get( attributeName );
        if ( !admins.contains( userRepresentation.getId() ) )
        {
            admins.add( userRepresentation.getId() );
        }

        groupsResource.group( groupRepresentation.getId() ).update( groupRepresentation );
    }

    /**
     * Unmarks a user as an admin of a group.
     *
     * This method makes use of a group metadata attribute, that holds all admins for the group. This method removes an
     * entry from that attribute value.
     *
     * This method modifies only the group metadata - it does not remove the user to the group.
     *
     * When the user has not been marked as an admin for the group, no changes are applied.
     *
     * Even when the group is not changed, an invocation of this method will cause an update in keycloak to be executed.
     *
     * @param groupRepresentation The group of which the user should no longer be an admin (cannot be null).
     * @param userRepresentation  The user that is no longer an admin of the group (cannot be null).
     */
    protected void unmarkAsAdmin( GroupRepresentation groupRepresentation, UserRepresentation userRepresentation )
    {
        if ( groupRepresentation.getAttributes() != null )
        {
            final String attributeName = JiveGlobals.getProperty( "keycloak.group.admins", "group-admins" );
            if ( groupRepresentation.getAttributes().get( attributeName ) != null )
            {
                groupRepresentation.getAttributes().get( attributeName ).remove( userRepresentation.getId() );

                if ( groupRepresentation.getAttributes().get( attributeName ).isEmpty() )
                {
                    groupRepresentation.getAttributes().remove( attributeName );
                }
            }
        }

        groupsResource.group( groupRepresentation.getId() ).update( groupRepresentation );
    }
}
