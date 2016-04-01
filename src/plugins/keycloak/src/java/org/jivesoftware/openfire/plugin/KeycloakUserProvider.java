package org.jivesoftware.openfire.plugin;

import org.jivesoftware.openfire.plugin.keycloak.Keycloak;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserAlreadyExistsException;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.openfire.user.UserProvider;
import org.jivesoftware.util.JiveGlobals;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.UserRepresentation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * A user provider that is backed by a Keycloak instance.
 *
 * @author Guus der Kinderen, guus@goodbytes.nl
 */
public class KeycloakUserProvider implements UserProvider
{
    private final static Logger Log = LoggerFactory.getLogger( KeycloakUserProvider.class );

    private Keycloak keycloak = null;
    private UsersResource usersResource;

    public KeycloakUserProvider()
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

        usersResource = null;
    }

    private synchronized void initialize()
    {
        dispose();

        final String serverUrl = JiveGlobals.getProperty( "keycloak.url", "http://localhost:8080/auth" );
        final String realm = JiveGlobals.getProperty( "keycloak.realm", "amisnuage" );
        final String username = JiveGlobals.getProperty( "keycloak.username", "admin" );
        final String password = JiveGlobals.getProperty( "keycloak.password", "admin" );
        final String clientId = JiveGlobals.getProperty( "keycloak.clientid", "openfire" );
        final String clientSecret = JiveGlobals.getProperty( "keycloak.clientsecret", "6817c4a7-7cbb-4fe1-9182-cf61b28f71ed" );

        keycloak = Keycloak.getInstance( serverUrl, realm, username, password, clientId, clientSecret );
        usersResource = keycloak.realm( realm ).users();

        // Verify that communication with the keycloak server is possible.
        usersResource.search( "test", null, null, null, 0, 1 );
    }

    /**
     * Creates an Openfire 'User' instance from a Keycloak 'user representation'.
     *
     * @param userRepresentation A user from keycloak (cannot be null)
     * @return An Openfire user (never null).
     */
    protected static User asOpenfireUser( UserRepresentation userRepresentation )
    {
        final String username = userRepresentation.getUsername();
        final String email = userRepresentation.getEmail();

        String fullName = "";
        if ( userRepresentation.getFirstName() != null ) {
            fullName += userRepresentation.getFirstName();
            fullName += ' ';
        }
        if ( userRepresentation.getLastName() != null ) {
            fullName += userRepresentation.getLastName();
        }

        final Date creation;
        if ( userRepresentation.getCreatedTimestamp() != null)
        {
            creation = new Date( userRepresentation.getCreatedTimestamp() );
        }
        else
        {
            creation = null;
        }

        final Date lastModified = null;

        final User user = new User( username, fullName, email, creation, lastModified );

        // TODO We could add extended properties to user.getProperties(). We need to determine if information added there will be and/or is allowed to be public.
        return user;
    }

    @Override
    public User loadUser( String username ) throws UserNotFoundException
    {
        final List<UserRepresentation> results = usersResource.search( username, null, null, null, 0, Integer.MAX_VALUE );
        for ( UserRepresentation result : results ) { // assumes that the first exact username hit is correct (and thus unique).
            if (result.getUsername().equals(username)) {
                return asOpenfireUser( result );
            }
        }
        throw new UserNotFoundException();
    }

    @Override
    public User createUser( String username, String password, String name, String email ) throws UserAlreadyExistsException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void deleteUser( String username )
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public int getUserCount()
    {
        // TODO Improve on this! This retrieves all users (and then counts them), which is very inefficient.
        return usersResource.search( null, 0, Integer.MAX_VALUE ).size();
    }

    @Override
    public Collection<User> getUsers()
    {
        final List<UserRepresentation> userRepresentations = usersResource.search( null, 0, Integer.MAX_VALUE );
        final List<User> result = new ArrayList<>( userRepresentations.size() );
        for ( UserRepresentation userRepresentation : userRepresentations )
        {
            result.add( asOpenfireUser( userRepresentation ) );
        }
        return Collections.unmodifiableList( result );
    }

    @Override
    public Collection<String> getUsernames()
    {
        final Collection<User> users = getUsers();
        final List<String> result = new ArrayList<>( users.size() );
        for ( User user : users ) {
            result.add( user.getUsername() );
        }

        return Collections.unmodifiableList( result );
    }

    @Override
    public Collection<User> getUsers( int startIndex, int numResults )
    {
        final List<UserRepresentation> userRepresentations = usersResource.search( null, startIndex, numResults );
        final List<User> result = new ArrayList<>( userRepresentations.size() );
        for ( UserRepresentation userRepresentation : userRepresentations )
        {
            result.add( asOpenfireUser( userRepresentation ) );
        }
        return Collections.unmodifiableList( result );
    }

    @Override
    public void setName( String username, String name ) throws UserNotFoundException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setEmail( String username, String email ) throws UserNotFoundException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setCreationDate( String username, Date creationDate ) throws UserNotFoundException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public void setModificationDate( String username, Date modificationDate ) throws UserNotFoundException
    {
        throw new UnsupportedOperationException();
    }

    @Override
    public Set<String> getSearchFields() throws UnsupportedOperationException
    {
        return new LinkedHashSet<>(Arrays.asList("Username", "Email"));
    }

    @Override
    public Collection<User> findUsers( Set<String> fields, String query ) throws UnsupportedOperationException
    {
        return findUsers( fields, query, 0, Integer.MAX_VALUE );
    }

    @Override
    public Collection<User> findUsers( Set<String> fields, String query, int startIndex, int numResults ) throws UnsupportedOperationException
    {
        if (!getSearchFields().containsAll(fields)) {
            throw new IllegalArgumentException("Search fields " + fields + " are not valid.");
        }

        // Keycloak will check for partial matches, but does not recognize wildcard characters.
        query = query.replaceAll( "\\*", "" );

        final Set<UserRepresentation> matchingUserRepresentations = new HashSet<>();
        if ( fields.contains( "Username" ) )
        {
            matchingUserRepresentations.addAll( usersResource.search( query, null, null, null, 0, Integer.MAX_VALUE ) );
        }

        if ( fields.contains( "Email" ) )
        {
            matchingUserRepresentations.addAll( usersResource.search( null, null, null, query, 0, Integer.MAX_VALUE ) );
        }

        final Set<User> result = new HashSet<>();
        for ( UserRepresentation userRepresentation : matchingUserRepresentations ) {
            result.add( asOpenfireUser( userRepresentation ));
        }

        return new ArrayList<>( result ).subList( startIndex, numResults > result.size() ? result.size() : numResults );
    }

    @Override
    public boolean isReadOnly()
    {
        return true;
    }

    @Override
    public boolean isNameRequired()
    {
        return false;
    }

    @Override
    public boolean isEmailRequired()
    {
        return false;
    }
}
