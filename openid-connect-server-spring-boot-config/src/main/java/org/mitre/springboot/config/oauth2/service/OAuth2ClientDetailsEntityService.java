package org.mitre.springboot.config.oauth2.service;

import java.util.Date;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import org.apache.http.impl.client.HttpClientBuilder;
import org.mitre.oauth2.model.ClientDetailsEntity;
import org.mitre.oauth2.model.ClientDetailsEntity.AuthMethod;
import org.mitre.oauth2.model.SystemScope;
import org.mitre.oauth2.repository.OAuth2ClientRepository;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.service.BlacklistedSiteService;
import org.mitre.openid.connect.service.StatsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;

@Service
public class OAuth2ClientDetailsEntityService extends DefaultOAuth2ClientDetailsEntityService {

    private OAuth2ClientRepository clientRepository;

    private BlacklistedSiteService blacklistedSiteService;

    private StatsService statsService;

    private ConfigurationPropertiesBean config;

    private SystemScopeService scopeService;

    private PasswordEncoder passwordEncoder;

    // map of sector URI -> list of redirect URIs
    private LoadingCache<String, List<String>> sectorRedirects = CacheBuilder.newBuilder()
            .expireAfterAccess(1, TimeUnit.HOURS).maximumSize(100)
            .build(new SectorIdentifierLoader(HttpClientBuilder.create().useSystemProperties().build(), config));

    @Autowired
    public OAuth2ClientDetailsEntityService(OAuth2ClientRepository clientRepository,
            BlacklistedSiteService blacklistedSiteService,
            StatsService statsService,
            ConfigurationPropertiesBean config,
            SystemScopeService scopeService,
            @Qualifier("clientPasswordEncoder") PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.blacklistedSiteService = blacklistedSiteService;
        this.statsService = statsService;
        this.config = config;
        this.scopeService = scopeService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public ClientDetailsEntity saveNewClient(ClientDetailsEntity client) {

        if (client.getId() != null) { // if it's not null, it's already been saved, this is an error
            throw new IllegalArgumentException("Tried to save a new client with an existing ID: " + client.getId());
        }

        if (client.getRegisteredRedirectUri() != null) {
            for (String uri : client.getRegisteredRedirectUri()) {
                if (blacklistedSiteService.isBlacklisted(uri)) {
                    throw new IllegalArgumentException("Client URI is blacklisted: " + uri);
                }
            }
        }

        // assign a random clientid if it's empty
        // NOTE: don't assign a random client secret without asking, since public clients have no secret
        if (Strings.isNullOrEmpty(client.getClientId())) {
            client = generateClientId(client);
        }

        // make sure that clients with the "refresh_token" grant type have the "offline_access" scope, and vice versa
        ensureRefreshTokenConsistency(client);

        // make sure we don't have both a JWKS and a JWKS URI
        ensureKeyConsistency(client);

        // check consistency when using HEART mode
        checkHeartMode(client);

        // timestamp this to right now
        client.setCreatedAt(new Date());

        // check the sector URI
        checkSectorIdentifierUri(client);

        ensureNoReservedScopes(client);

        // encode password
        client.setClientSecret(encodePassword(client.getClientSecret()));

        ClientDetailsEntity savedClient = clientRepository.saveClient(client);

        statsService.resetCache();

        return savedClient;
    }

    @Override
    public ClientDetailsEntity updateClient(ClientDetailsEntity oldClient, ClientDetailsEntity newClient)
            throws IllegalArgumentException {
        
        if (oldClient != null && newClient != null) {

            for (String uri : newClient.getRegisteredRedirectUri()) {
                if (blacklistedSiteService.isBlacklisted(uri)) {
                    throw new IllegalArgumentException("Client URI is blacklisted: " + uri);
                }
            }

            // if the client is flagged to allow for refresh tokens, make sure it's got the right scope
            ensureRefreshTokenConsistency(newClient);

            // make sure we don't have both a JWKS and a JWKS URI
            ensureKeyConsistency(newClient);

            // check consistency when using HEART mode
            checkHeartMode(newClient);

            // check the sector URI
            checkSectorIdentifierUri(newClient);

            // make sure a client doesn't get any special system scopes
            ensureNoReservedScopes(newClient);

            // encode password
            if (!oldClient.getClientSecret().equals(newClient.getClientSecret())) {
                newClient.setClientSecret(encodePassword(newClient.getClientSecret()));
            }

            return clientRepository.updateClient(oldClient.getId(), newClient);
        }
        
        throw new IllegalArgumentException("Neither old client or new client can be null!");
    }

    private void ensureRefreshTokenConsistency(ClientDetailsEntity client) {
        if (client.getAuthorizedGrantTypes().contains("refresh_token")
                || client.getScope().contains(SystemScopeService.OFFLINE_ACCESS)) {
            client.getScope().add(SystemScopeService.OFFLINE_ACCESS);
            client.getAuthorizedGrantTypes().add("refresh_token");
        }
    }

    private void ensureKeyConsistency(ClientDetailsEntity client) {
        if (client.getJwksUri() != null && client.getJwks() != null) {
            // a client can only have one key type or the other, not both
            throw new IllegalArgumentException("A client cannot have both JWKS URI and JWKS value");
        }
    }

    private void checkHeartMode(ClientDetailsEntity client) {
        
        if (config.isHeartMode()) {
            
            if (client.getGrantTypes().contains("authorization_code")) {
                // make sure we don't have incompatible grant types
                if (client.getGrantTypes().contains("implicit")
                        || client.getGrantTypes().contains("client_credentials")) {
                    throw new IllegalArgumentException("[HEART mode] Incompatible grant types");
                }

                // make sure we've got the right authentication method
                if (client.getTokenEndpointAuthMethod() == null
                        || !client.getTokenEndpointAuthMethod().equals(AuthMethod.PRIVATE_KEY)) {
                    throw new IllegalArgumentException(
                            "[HEART mode] Authorization code clients must use the private_key authentication method");
                }

                // make sure we've got a redirect URI
                if (client.getRedirectUris().isEmpty()) {
                    throw new IllegalArgumentException(
                            "[HEART mode] Authorization code clients must register at least one redirect URI");
                }
            }

            if (client.getGrantTypes().contains("implicit")) {
                // make sure we don't have incompatible grant types
                if (client.getGrantTypes().contains("authorization_code")
                        || client.getGrantTypes().contains("client_credentials")
                        || client.getGrantTypes().contains("refresh_token")) {
                    throw new IllegalArgumentException("[HEART mode] Incompatible grant types");
                }

                // make sure we've got the right authentication method
                if (client.getTokenEndpointAuthMethod() == null
                        || !client.getTokenEndpointAuthMethod().equals(AuthMethod.NONE)) {
                    throw new IllegalArgumentException(
                            "[HEART mode] Implicit clients must use the none authentication method");
                }

                // make sure we've got a redirect URI
                if (client.getRedirectUris().isEmpty()) {
                    throw new IllegalArgumentException(
                            "[HEART mode] Implicit clients must register at least one redirect URI");
                }
            }

            if (client.getGrantTypes().contains("client_credentials")) {
                // make sure we don't have incompatible grant types
                if (client.getGrantTypes().contains("authorization_code") || client.getGrantTypes().contains("implicit")
                        || client.getGrantTypes().contains("refresh_token")) {
                    throw new IllegalArgumentException("[HEART mode] Incompatible grant types");
                }

                // make sure we've got the right authentication method
                if (client.getTokenEndpointAuthMethod() == null
                        || !client.getTokenEndpointAuthMethod().equals(AuthMethod.PRIVATE_KEY)) {
                    throw new IllegalArgumentException(
                            "[HEART mode] Client credentials clients must use the private_key authentication method");
                }

                // make sure we've got a redirect URI
                if (!client.getRedirectUris().isEmpty()) {
                    throw new IllegalArgumentException(
                            "[HEART mode] Client credentials clients must not register a redirect URI");
                }
            }

            if (client.getGrantTypes().contains("password")) {
                throw new IllegalArgumentException("[HEART mode] Password grant type is forbidden");
            }

            // make sure we don't have a client secret
            if (!Strings.isNullOrEmpty(client.getClientSecret())) {
                throw new IllegalArgumentException("[HEART mode] Client secrets are not allowed");
            }

            // make sure we've got a key registered
            if (client.getJwks() == null && Strings.isNullOrEmpty(client.getJwksUri())) {
                throw new IllegalArgumentException("[HEART mode] All clients must have a key registered");
            }

            // make sure our redirect URIs each fit one of the allowed categories
            if (client.getRedirectUris() != null && !client.getRedirectUris().isEmpty()) {
                
                boolean localhost = false;
                boolean remoteHttps = false;
                boolean customScheme = false;
                
                for (String uri : client.getRedirectUris()) {
                    
                    final UriComponents components = UriComponentsBuilder.fromUriString(uri).build();
                    
                    if (components.getScheme() == null) {
                        // this is a very unknown redirect URI
                        customScheme = true;
                    } else if (components.getScheme().equals("http")) {
                        // http scheme, check for localhost
                        if (components.getHost().equals("localhost") || components.getHost().equals("127.0.0.1")) {
                            localhost = true;
                        } else {
                            throw new IllegalArgumentException("[HEART mode] Can't have an http redirect URI on non-local host");
                        }
                    } else if (components.getScheme().equals("https")) {
                        remoteHttps = true;
                    } else {
                        customScheme = true;
                    }
                }

                // now we make sure the client has a URI in only one of each of the three categories
                if (!((localhost ^ remoteHttps ^ customScheme) && !(localhost && remoteHttps && customScheme))) {
                    throw new IllegalArgumentException("[HEART mode] Can't have more than one class of redirect URI");
                }
            }
        }
    }

    private void checkSectorIdentifierUri(ClientDetailsEntity client) {

        if (!Strings.isNullOrEmpty(client.getSectorIdentifierUri())) {

            try {

                final List<String> redirects = sectorRedirects.get(client.getSectorIdentifierUri());

                if (client.getRegisteredRedirectUri() != null) {
                    for (String uri : client.getRegisteredRedirectUri()) {
                        if (!redirects.contains(uri)) {
                            throw new IllegalArgumentException("Requested Redirect URI " + uri
                                    + " is not listed at sector identifier " + redirects);
                        }
                    }
                }

            } catch (UncheckedExecutionException | ExecutionException e) {
                throw new IllegalArgumentException("Unable to load sector identifier URI "
                        + client.getSectorIdentifierUri() + ": " + e.getMessage());
            }
        }
    }

    /**
     * Make sure the client doesn't request any system reserved scopes
     */
    private void ensureNoReservedScopes(ClientDetailsEntity client) {
        // make sure a client doesn't get any special system scopes
        Set<SystemScope> requestedScope = scopeService.fromStrings(client.getScope());
        requestedScope = scopeService.removeReservedScopes(requestedScope);
        client.setScope(scopeService.toStrings(requestedScope));
    }

    private String encodePassword(String password) {
        return passwordEncoder.encode(password);
    }

}