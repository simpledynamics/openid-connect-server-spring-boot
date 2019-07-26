package org.mitre.springboot.config.openid.connect;

import javax.servlet.Filter;

import org.mitre.openid.connect.view.JWKSetView;
import org.mitre.openid.connect.web.JWKSetPublishingEndpoint;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;

@Order(150)
@Configuration
@ConditionalOnProperty(havingValue="true", name="openid.connect.endpoints.oidc.jwksetpublishing.enabled", matchIfMissing=true)
public class JwkWebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	protected Http403ForbiddenEntryPoint http403ForbiddenEntryPoint;
	
	@Bean
	@ConditionalOnMissingBean(JWKSetPublishingEndpoint.class)
	protected JWKSetPublishingEndpoint JWKSetPublishingEndpoint()  {
		return new JWKSetPublishingEndpoint();
	}
	
	@Bean(name=JWKSetView.VIEWNAME)
	@ConditionalOnMissingBean(name=JWKSetView.VIEWNAME)
	protected JWKSetView jwkSet()  {
		return new JWKSetView();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		// @formatter:off
		http
			.requestMatchers()
				.antMatchers("/jwk**")
				.and()
			.exceptionHandling()
				.authenticationEntryPoint(http403ForbiddenEntryPoint)
				.and()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and()
		.authorizeRequests()
			.antMatchers("/jwk**")
			.permitAll()
		;
		// @formatter:on
	}
}
