package org.jivesoftware.openfire.plugin.keycloak;

import org.jboss.resteasy.client.jaxrs.ResteasyClient;
import org.jboss.resteasy.client.jaxrs.ResteasyWebTarget;
import org.keycloak.admin.client.Config;
import org.keycloak.admin.client.resource.BasicAuthFilter;
import org.keycloak.admin.client.token.TokenService;
import org.keycloak.common.util.Time;
import org.keycloak.representations.AccessTokenResponse;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.NotAuthorizedException;
import javax.ws.rs.core.Form;

/**
 * This is org.keycloak.admin.client.token.TokenManager, modified to have the tokenService be proxied in the
 * constructor. This will avoid classloading problems where the constructor and calling threads are spawn from different
 * classloaders.
 *
 * @author Guus der Kinderen, guus.der.kinderen@gmail.com
 */
public class TokenManager extends org.keycloak.admin.client.token.TokenManager
{
    private static final long DEFAULT_MIN_VALIDITY = 30;

    private final TokenService tokenService;
    private AccessTokenResponse currentToken;
    private long expirationTime;
    private long minTokenValidity = DEFAULT_MIN_VALIDITY;
    private final Config config;

    public TokenManager(Config config, ResteasyClient client){
        super(config, client);

        this.config = config;

        ResteasyWebTarget target = client.target(config.getServerUrl());
        if( !config.isPublicClient() )
        {
            target.register(new BasicAuthFilter(config.getClientId(), config.getClientSecret()));
        }
        tokenService = target.proxy(TokenService.class);
    }

    @Override
    public String getAccessTokenString(){
        return getAccessToken().getToken();
    }

    @Override
    public AccessTokenResponse getAccessToken(){
        if(currentToken == null){
            grantToken();
        }else if(tokenExpired()){
            refreshToken();
        }
        return currentToken;
    }

    @Override
    public AccessTokenResponse grantToken(){
        Form form = new Form()
                .param("grant_type", "password")
                .param("username", config.getUsername())
                .param("password", config.getPassword());

        if(config.isPublicClient()){
            form.param("client_id", config.getClientId());
        }

        int requestTime = Time.currentTime();
        currentToken = tokenService.grantToken(config.getRealm(), form.asMap());
        expirationTime = requestTime + currentToken.getExpiresIn();

        return currentToken;
    }

    @Override
    public AccessTokenResponse refreshToken(){
        Form form = new Form()
                .param("grant_type", "refresh_token")
                .param("refresh_token", currentToken.getRefreshToken());

        if(config.isPublicClient()){
            form.param("client_id", config.getClientId());
        }

        try {
            int requestTime = Time.currentTime();
            currentToken = tokenService.refreshToken(config.getRealm(), form.asMap());
            expirationTime = requestTime + currentToken.getExpiresIn();

            return currentToken;
        } catch (BadRequestException e) {
            return grantToken();
        } catch (NotAuthorizedException e) {
            return grantToken();
        }
    }

    @Override
    public void setMinTokenValidity(long minTokenValidity) {
        this.minTokenValidity = minTokenValidity;
    }

    private boolean tokenExpired() {
        return (Time.currentTime() + minTokenValidity) >= expirationTime;
    }

    /**
     * Invalidates the current token, but only when it is equal to the token passed as an argument.
     *
     * @param token the token to invalidate (cannot be null).
     */
    @Override
    public void invalidate(String token) {
        if (currentToken == null) {
            return; // There's nothing to invalidate.
        }
        if (token.equals(currentToken.getToken())) {
            // When used next, this cause a refresh attempt, that in turn will cause a grant attempt if refreshing fails.
            expirationTime = -1;
        }
    }
}
