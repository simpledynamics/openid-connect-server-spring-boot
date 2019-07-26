package org.mitre.springboot.samples;

import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.springboot.config.annotation.EnableOpenIDConnectServer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

@SpringBootApplication
@EnableOpenIDConnectServer
public class DefaultApplication {

	public static void main(String[] args) {
		SpringApplication.run(DefaultApplication.class, args);
	}

}
