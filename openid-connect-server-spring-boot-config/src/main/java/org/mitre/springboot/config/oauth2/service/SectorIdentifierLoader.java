package org.mitre.springboot.config.oauth2.service;

import java.util.ArrayList;
import java.util.List;

import org.apache.http.client.HttpClient;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.google.common.cache.CacheLoader;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

/**
 * Utility class to load a sector identifier's set of authorized redirect URIs.
 *
 */
class SectorIdentifierLoader extends CacheLoader<String, List<String>> {
    
    private static final Logger logger = LoggerFactory.getLogger(SectorIdentifierLoader.class);
    
    private ConfigurationPropertiesBean config;
    private HttpComponentsClientHttpRequestFactory httpFactory;
    private RestTemplate restTemplate;
    private JsonParser parser = new JsonParser();

    @Autowired
    SectorIdentifierLoader(HttpClient httpClient, ConfigurationPropertiesBean config) {
        this.httpFactory = new HttpComponentsClientHttpRequestFactory(httpClient);
        this.restTemplate = new RestTemplate(httpFactory);
        this.config = config;
    }

    @Override
    public List<String> load(String key) throws Exception {

        if (!key.startsWith("https")) {
            if (config.isForceHttps()) {
                throw new IllegalArgumentException("Sector identifier must start with https: " + key);
            }
            logger.error("Sector identifier doesn't start with https, loading anyway...");
        }

        // key is the sector URI
        final String jsonString = restTemplate.getForObject(key, String.class);
        final JsonElement json = parser.parse(jsonString);

        if (json.isJsonArray()) {
            
            final List<String> redirectUris = new ArrayList<>();
            
            for (JsonElement el : json.getAsJsonArray()) {
                redirectUris.add(el.getAsString());
            }

            logger.info("Found " + redirectUris + " for sector " + key);

            return redirectUris;
            
        } else {
            throw new IllegalArgumentException("JSON Format Error");
        }

    }

}
