package org.mitre.springboot.config.openid.connect;

import javax.servlet.Filter;

import org.mitre.openid.connect.view.ClientInformationResponseView;
import org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

@Configuration
@ConditionalOnProperty(havingValue="true", name="openid.connect.endpoints.oidc.dynamicclientregistration.enabled", matchIfMissing=true)
@Order(200)
public class DynamicClientRegistrationResourceServerConfig extends ResourceServerConfigurerAdapter {
	String PATTERN = "/" + org.mitre.openid.connect.web.DynamicClientRegistrationEndpoint.URL + "/**";
	
	@Autowired
	protected OAuth2AuthenticationEntryPoint authenticationEntryPoint; 
	
	@Bean
	@ConditionalOnMissingBean(DynamicClientRegistrationEndpoint.class)
	protected DynamicClientRegistrationEndpoint DynamicClientRegistrationEndpoint()  {
		return new DynamicClientRegistrationEndpoint();
	}
	
	@Bean(name=ClientInformationResponseView.VIEWNAME)
	@ConditionalOnMissingBean(name=ClientInformationResponseView.VIEWNAME)
	protected ClientInformationResponseView clientInformationResponseView()  {
		return new ClientInformationResponseView();
	}
	
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.requestMatchers()
				.antMatchers(PATTERN)
				.and()
			.exceptionHandling().authenticationEntryPoint(authenticationEntryPoint)
				.and()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
			.authorizeRequests()
				.antMatchers(PATTERN)
				.permitAll()
		;
		// @formatter:on
	}
}
