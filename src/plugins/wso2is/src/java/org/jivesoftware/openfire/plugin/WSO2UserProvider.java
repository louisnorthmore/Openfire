package org.jivesoftware.openfire.plugin;

import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserAlreadyExistsException;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.openfire.user.UserProvider;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.wso2.carbon.authenticator.stub.LoginAuthenticationExceptionException;
import org.wso2.carbon.um.ws.api.WSRealmBuilder;
import org.wso2.carbon.user.core.UserRealm;
import org.wso2.carbon.user.core.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.wso2.carbon.user.core.claim.Claim;

import java.net.MalformedURLException;
import java.rmi.RemoteException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Created by guus on 26-2-16.
 */
public class WSO2UserProvider extends WSO2ISServiceStub implements UserProvider
{
    private final static Logger Log = LoggerFactory.getLogger( WSO2UserProvider.class );

    private final static String SERVER_URL = "https://localhost:9443/services/";

    public WSO2UserProvider()
    {
    }

    protected UserStoreManager getUserStoreManager() throws UserStoreException, RemoteException, LoginAuthenticationExceptionException, MalformedURLException
    {
        login(); // TODO It is silly (and not thread safe) to log in for each request. Cache this, re-login only when cookies expire.
        ConfigurationContext configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem( "/home/guus/Downloads/wso2is-5.1.0/repository/conf/axis2/", "/home/guus/Downloads/wso2is-5.1.0/repository/conf/axis2/axis2_client.xml" );
        UserRealm realm = WSRealmBuilder.createWSRealm(SERVER_URL, cookie, configContext);
        return realm.getUserStoreManager();
    }

    @Override
    public User loadUser( String id ) throws UserNotFoundException
    {
        try
        {
            final String usernameClaimUri = JiveGlobals.getProperty( "wso2is.claims.username.uri", "http://wso2.org/claims/username" );
            String username = id;

            final String nameClaimUri = JiveGlobals.getProperty( "wso2is.claims.fullname.uri", "http://wso2.org/claims/fullname" );
            String name = null;

            final String emailClaimUri = JiveGlobals.getProperty( "wso2is.claims.emailaddress.uri", "http://wso2.org/claims/emailaddress" );
            String email = null;

            final String createdClaimUri = JiveGlobals.getProperty( "wso2is.claims.created.uri", "urn:scim:schemas:core:1.0:meta.created" );
            Date creationDate = null;

            final String lastModifiedClaimUri = JiveGlobals.getProperty( "wso2is.claims.lastmodified.uri", "urn:scim:schemas:core:1.0:meta.lastModified" );
            Date modificationDate = null;

            final Claim[] claims = getUserStoreManager().getUserClaimValues( username, null );
            for (Claim claim : claims) {
                final String uri = claim.getClaimUri();
                final String value = claim.getValue();
                Log.info( "Iterating over claim '{}': '{}'.", uri, value);

                if ( uri.equalsIgnoreCase( usernameClaimUri ) )
                {
                    username = value;
                }
                else if ( uri.equalsIgnoreCase( nameClaimUri ) )
                {
                    name = value;
                }
                else if ( uri.equalsIgnoreCase( emailClaimUri) )
                {
                    email = value;
                }
                else if ( uri.equalsIgnoreCase( createdClaimUri) )
                {
                    try
                    {
                        creationDate = new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss" ).parse( value );
                    } catch ( ParseException ex ) {
                        Log.debug( "Unable to parse creation date object from '{}' returned for user '{}'.", value, id, ex );
                    }
                }
                else if ( uri.equalsIgnoreCase( lastModifiedClaimUri) )
                {
                    try
                    {
                        modificationDate = new SimpleDateFormat( "yyyy-MM-dd'T'HH:mm:ss" ).parse( value );
                    } catch ( ParseException ex ) {
                        Log.debug( "Unable to parse last modification date from '{}' returned for user '{}'.", value, id, ex );
                    }
                }
            }
            return new User( username, name, email, creationDate, modificationDate );
        }
        catch ( Exception e )
        {
            Log.debug( "Unable to load user: " + id, e );
            throw new UserNotFoundException( "Unable to retrieve user '"+id+"'", e);
        }
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
        return getUsernames().size();
    }

    @Override
    public Collection<User> getUsers()
    {
        try
        {
            final List<String> usernames = getUsernames();
            final Collection<User> results = new ArrayList<>( usernames.size() );
            for ( String username : usernames ) {
                final User user = loadUser( username );
                results.add( user );
            }

            return results;
        }
        catch ( UserNotFoundException ex )
        {
            // This should be rare, as the list of user names is retrieved from the same source. Potential concurrency issue.
            throw new RuntimeException( "Unable to obtain users.", ex );
        }
    }

    @Override
    public List<String> getUsernames()
    {
        final Set<String> search = new HashSet<>();
        search.add( "Username" );
        return findUsernames( search, "*" );
    }

    @Override
    public Collection<User> getUsers( int startIndex, int numResults )
    {
        try
        {
            final List<String> usernames = getUsernames();
            final Collection<User> results = new ArrayList<>( numResults );
            for ( int i = startIndex; i < numResults && i < usernames.size(); i++ )
            {
                final User user = loadUser( usernames.get( i ) );
                results.add( user );
            }

            return results;
        }
        catch ( UserNotFoundException ex )
        {
            // This should be rare, as the list of user names is retrieved from the same source. Potential concurrency issue.
            throw new RuntimeException( "Unable to obtain users.", ex );
        }
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
        final Set<String> results = new HashSet<>();
        results.add( "Username" );
        return results;
    }

    public List<String> findUsernames( Set<String> fields, String query ) throws UnsupportedOperationException
    {
        if (!getSearchFields().containsAll(fields)) {
            throw new IllegalArgumentException("Search fields " + fields + " are not valid.");
        }

        try
        {
            return Collections.unmodifiableList( Arrays.asList( getUserStoreManager().listUsers( query, -1 ) ) );
        }
        catch ( MalformedURLException | UserStoreException | RemoteException | LoginAuthenticationExceptionException ex )
        {
            throw new RuntimeException( "Unable to obtain users.", ex );
        }
    }

    @Override
    public Collection<User> findUsers( Set<String> fields, String query ) throws UnsupportedOperationException
    {
        try
        {
            final List<String> usernames = findUsernames( fields, query );
            final Collection<User> results = new ArrayList<>( usernames.size() );
            for ( String username : usernames ) {
                final User user = loadUser( username );
                results.add( user );
            }
            return results;
        }
        catch ( UserNotFoundException ex )
        {
            // This should be rare, as the list of user names is retrieved from the same source. Potential concurrency issue.
            throw new RuntimeException( "Unable to obtain users.", ex );
        }
    }

    @Override
    public Collection<User> findUsers( Set<String> fields, String query, int startIndex, int numResults ) throws UnsupportedOperationException
    {
        try
        {
            final List<String> usernames = findUsernames( fields, query );
            final Collection<User> results = new ArrayList<>( numResults );
            for ( int i = startIndex; i < numResults && i < usernames.size(); i++ )
            {
                final User user = loadUser( usernames.get( i ) );
                results.add( user );
            }

            return results;
        }
        catch ( UserNotFoundException ex )
        {
            // This should be rare, as the list of user names is retrieved from the same source. Potential concurrency issue.
            throw new RuntimeException( "Unable to obtain users.", ex );
        }
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
