package org.mitre.springboot.config.oauth2;

import java.util.Collections;
import java.util.HashSet;

import javax.servlet.Filter;

import org.mitre.oauth2.web.IntrospectionEndpoint;
import org.mitre.oauth2.web.RevocationEndpoint;
import org.mitre.openid.connect.assertion.JWTBearerAuthenticationProvider;
import org.mitre.openid.connect.assertion.JWTBearerClientAssertionTokenEndpointFilter;
import org.mitre.openid.connect.filter.MultiUrlRequestMatcher;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.client.ClientCredentialsTokenEndpointFilter;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;

/**
 * Configuration of OAuth 2.0 endpoints for token management (granting, inspection and revocation)
 * @author barretttucker
 *
 */
@Configuration
@Order(110)
public class TokenWebSecurityConfig extends WebSecurityConfigurerAdapter{

    @Autowired
    protected OAuth2AuthenticationEntryPoint authenticationEntryPoint;

    @Autowired
    @Qualifier("clientUserDetailsService")
    protected UserDetailsService clientUserDetailsService;

    @Autowired
    @Qualifier("uriEncodedClientUserDetailsService")
    protected UserDetailsService uriEncodedClientUserDetailsService;

    @Autowired
    protected OAuth2AccessDeniedHandler oAuth2AccessDeniedHandler;

    @Autowired
    @Lazy
    protected ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter;

    @Autowired
    @Lazy
    protected JWTBearerClientAssertionTokenEndpointFilter jwtBearerClientAssertionTokenEndpointFilter;

    @Autowired
    @Qualifier("clientPasswordEncoder")
    private PasswordEncoder clientPasswordEncoder;

    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception{
        auth.userDetailsService(clientUserDetailsService).passwordEncoder(clientPasswordEncoder);
        auth.userDetailsService(uriEncodedClientUserDetailsService).passwordEncoder(clientPasswordEncoder);
    }

    @Bean
    @ConditionalOnMissingBean(IntrospectionEndpoint.class)
    protected IntrospectionEndpoint introspectionEndpoint(){
        return new IntrospectionEndpoint();
    }

    @Bean
    @ConditionalOnMissingBean(RevocationEndpoint.class)
    protected RevocationEndpoint revocationEndpoint(){
        return new RevocationEndpoint();
    }

    @Bean
    @Autowired
    @ConditionalOnMissingBean(ClientCredentialsTokenEndpointFilter.class)
    public ClientCredentialsTokenEndpointFilter clientCredentialsTokenEndpointFilter(
            @Qualifier("clientAuthenticationMatcher")
            final MultiUrlRequestMatcher clientAuthenticationMatcher) throws Exception{
        final ClientCredentialsTokenEndpointFilter filter = new ClientCredentialsTokenEndpointFilter();
        filter.setRequiresAuthenticationRequestMatcher(clientAuthenticationMatcher);
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }

    @Autowired
    @Bean
    @ConditionalOnMissingBean(JWTBearerClientAssertionTokenEndpointFilter.class)
    public JWTBearerClientAssertionTokenEndpointFilter jwtBearerClientAssertionTokenEndpointFilter(
            @Qualifier("clientAuthenticationMatcher")
            final MultiUrlRequestMatcher clientAuthenticationMatcher, final JWTBearerAuthenticationProvider jwtBearerAuthenticationProvider){
        final JWTBearerClientAssertionTokenEndpointFilter filter = new JWTBearerClientAssertionTokenEndpointFilter(
                clientAuthenticationMatcher);
        filter.setAuthenticationManager(new ProviderManager(
                Collections.<AuthenticationProvider> singletonList(jwtBearerAuthenticationProvider)));
        return filter;
    }

    @Bean
    @ConditionalOnMissingBean(JWTBearerAuthenticationProvider.class)
    public JWTBearerAuthenticationProvider jwtBearerAuthenticationProvider(){
        return new JWTBearerAuthenticationProvider();
    }

    @Bean(name = "clientAuthenticationMatcher")
    @ConditionalOnMissingBean(type = {
            "javax.servlet.http.HttpServletRequest.MultiUrlRequestMatcher"}, name = "clientAuthenticationMatcher")
    public MultiUrlRequestMatcher clientAuthenticationMatcher(){
        final HashSet<String> urls = new HashSet<String>();
        urls.add("/introspect");
        urls.add("/revoke");
        urls.add("/token");
        return new MultiUrlRequestMatcher(urls);
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception{
        // @formatter:off
		http
			.requestMatchers()
				.antMatchers(
						"/token", 
						"/"+IntrospectionEndpoint.URL+"**", 
						"/"+RevocationEndpoint.URL+"**")
				.and()
			.httpBasic()
				.authenticationEntryPoint(authenticationEntryPoint)
				.and()
			.authorizeRequests()
				.antMatchers(HttpMethod.OPTIONS, "/token").permitAll()
				.antMatchers("/token").authenticated()
				.and()
			.addFilterAfter(jwtBearerClientAssertionTokenEndpointFilter, AbstractPreAuthenticatedProcessingFilter.class)
			.addFilterAfter(clientCredentialsTokenEndpointFilter, BasicAuthenticationFilter.class)	

			.exceptionHandling()
				.authenticationEntryPoint(authenticationEntryPoint)
				.accessDeniedHandler(oAuth2AccessDeniedHandler)
				.and()
			.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		;
		// @formatter:on
    }
}
