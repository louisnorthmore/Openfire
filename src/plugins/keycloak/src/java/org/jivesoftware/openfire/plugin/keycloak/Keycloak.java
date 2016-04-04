package org.jivesoftware.openfire.plugin.keycloak;

import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyClientBuilder;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.keycloak.admin.client.resource.BearerAuthFilter;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.RealmsResource;
import org.keycloak.admin.client.resource.ServerInfoResource;

import org.keycloak.admin.client.Config;

import java.net.URI;

/**
 * This is a copy of org.keycloak.admin.client.Keycloak, with two modifications:
 *  - a different Token manager is used (which itself introduces a modification)
 *  - an additional getInstance is used to be able to override the Resteasy client.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class Keycloak {

    private final Config config;
    private final TokenManager tokenManager;
    private final ResteasyWebTarget target;
    private final ResteasyClient client;

    Keycloak(String serverUrl, String realm, String username, String password, String clientId, String clientSecret, ResteasyClient resteasyClient){
        config = new Config(serverUrl, realm, username, password, clientId, clientSecret);
        client = resteasyClient != null ? resteasyClient : new ResteasyClientBuilder().build();

        tokenManager = new TokenManager(config, client);

        target = client.target(config.getServerUrl());

        target.register(new BearerAuthFilter(tokenManager));
    }

    public static Keycloak getInstance(String serverUrl, String realm, String username, String password, String clientId, String clientSecret, ResteasyClient resteasyClient){
        return new Keycloak(serverUrl, realm, username, password, clientId, clientSecret, resteasyClient);
    }

    public static Keycloak getInstance(String serverUrl, String realm, String username, String password, String clientId, String clientSecret){
        return new Keycloak(serverUrl, realm, username, password, clientId, clientSecret, null);
    }

    public static Keycloak getInstance(String serverUrl, String realm, String username, String password, String clientId){
        return new Keycloak(serverUrl, realm, username, password, clientId, null, null);
    }

    public RealmsResource realms(){
        return target.proxy(RealmsResource.class);
    }

    public RealmResource realm(String realmName){
        return realms().realm(realmName);
    }

    public ServerInfoResource serverInfo(){
        return target.proxy(ServerInfoResource.class);
    }

    public TokenManager tokenManager(){
        return tokenManager;
    }

    /**
     * Create a secure proxy based on an absolute URI.
     * All set up with appropriate token
     *
     * @param proxyClass
     * @param absoluteURI
     * @param <T>
     * @return
     */
    public <T> T proxy(Class<T> proxyClass, URI absoluteURI) {
        return client.target(absoluteURI).register(new BearerAuthFilter(tokenManager)).proxy(proxyClass);
    }

    /**
     * Closes the underlying client. After calling this method, this <code>Keycloak</code> instance cannot be reused.
     */
    public void close() {
        client.close();
    }

}
