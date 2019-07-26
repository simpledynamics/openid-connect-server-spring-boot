package org.mitre.springboot.config;

import javax.servlet.Filter;

import org.mitre.jwt.assertion.AssertionValidator;
import org.mitre.jwt.assertion.impl.NullAssertionValidator;
import org.mitre.jwt.assertion.impl.WhitelistedIssuerAssertionValidator;
import org.mitre.jwt.signer.service.impl.ClientKeyCacheService;
import org.mitre.jwt.signer.service.impl.JWKSetCacheService;
import org.mitre.jwt.signer.service.impl.SymmetricKeyJWTValidatorCacheService;
import org.mitre.oauth2.assertion.AssertionOAuth2RequestFactory;
import org.mitre.oauth2.assertion.impl.DirectCopyRequestFactory;
import org.mitre.oauth2.repository.AuthenticationHolderRepository;
import org.mitre.oauth2.repository.AuthorizationCodeRepository;
import org.mitre.oauth2.repository.OAuth2ClientRepository;
import org.mitre.oauth2.repository.OAuth2TokenRepository;
import org.mitre.oauth2.repository.SystemScopeRepository;
import org.mitre.oauth2.repository.impl.JpaAuthenticationHolderRepository;
import org.mitre.oauth2.repository.impl.JpaAuthorizationCodeRepository;
import org.mitre.oauth2.repository.impl.JpaOAuth2ClientRepository;
import org.mitre.oauth2.repository.impl.JpaOAuth2TokenRepository;
import org.mitre.oauth2.repository.impl.JpaSystemScopeRepository;
import org.mitre.oauth2.service.ClientDetailsEntityService;
import org.mitre.oauth2.service.IntrospectionResultAssembler;
import org.mitre.oauth2.service.OAuth2TokenEntityService;
import org.mitre.oauth2.service.SystemScopeService;
import org.mitre.oauth2.service.impl.BlacklistAwareRedirectResolver;
import org.mitre.oauth2.service.impl.DefaultClientUserDetailsService;
import org.mitre.oauth2.service.impl.DefaultIntrospectionResultAssembler;
import org.mitre.oauth2.service.impl.DefaultOAuth2AuthorizationCodeService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ClientDetailsEntityService;
import org.mitre.oauth2.service.impl.DefaultOAuth2ProviderTokenService;
import org.mitre.oauth2.service.impl.DefaultSystemScopeService;
import org.mitre.oauth2.service.impl.UriEncodedClientUserDetailsService;
import org.mitre.oauth2.token.ChainedTokenGranter;
import org.mitre.oauth2.token.JWTAssertionTokenGranter;
import org.mitre.oauth2.token.ScopeServiceAwareOAuth2RequestValidator;
import org.mitre.oauth2.web.OAuthConfirmationController;
import org.mitre.openid.connect.config.ConfigurationPropertiesBean;
import org.mitre.openid.connect.filter.AuthorizationRequestFilter;
import org.mitre.openid.connect.repository.AddressRepository;
import org.mitre.openid.connect.repository.ApprovedSiteRepository;
import org.mitre.openid.connect.repository.BlacklistedSiteRepository;
import org.mitre.openid.connect.repository.PairwiseIdentifierRepository;
import org.mitre.openid.connect.repository.UserInfoRepository;
import org.mitre.openid.connect.repository.WhitelistedSiteRepository;
import org.mitre.openid.connect.repository.impl.JpaAddressRepository;
import org.mitre.openid.connect.repository.impl.JpaApprovedSiteRepository;
import org.mitre.openid.connect.repository.impl.JpaBlacklistedSiteRepository;
import org.mitre.openid.connect.repository.impl.JpaPairwiseIdentifierRepository;
import org.mitre.openid.connect.repository.impl.JpaUserInfoRepository;
import org.mitre.openid.connect.repository.impl.JpaWhitelistedSiteRepository;
import org.mitre.openid.connect.request.ConnectOAuth2RequestFactory;
import org.mitre.openid.connect.service.ApprovedSiteService;
import org.mitre.openid.connect.service.BlacklistedSiteService;
import org.mitre.openid.connect.service.ClientLogoLoadingService;
import org.mitre.openid.connect.service.OIDCTokenService;
import org.mitre.openid.connect.service.PairwiseIdentiferService;
import org.mitre.openid.connect.service.ScopeClaimTranslationService;
import org.mitre.openid.connect.service.StatsService;
import org.mitre.openid.connect.service.UserInfoService;
import org.mitre.openid.connect.service.WhitelistedSiteService;
import org.mitre.openid.connect.service.impl.DefaultApprovedSiteService;
import org.mitre.openid.connect.service.impl.DefaultBlacklistedSiteService;
import org.mitre.openid.connect.service.impl.DefaultOIDCTokenService;
import org.mitre.openid.connect.service.impl.DefaultScopeClaimTranslationService;
import org.mitre.openid.connect.service.impl.DefaultStatsService;
import org.mitre.openid.connect.service.impl.DefaultUserInfoService;
import org.mitre.openid.connect.service.impl.DefaultWhitelistedSiteService;
import org.mitre.openid.connect.service.impl.DummyResourceSetService;
import org.mitre.openid.connect.service.impl.InMemoryClientLogoLoadingService;
import org.mitre.openid.connect.service.impl.UUIDPairwiseIdentiferService;
import org.mitre.openid.connect.token.ConnectTokenEnhancer;
import org.mitre.openid.connect.token.TofuUserApprovalHandler;
import org.mitre.openid.connect.view.HttpCodeView;
import org.mitre.openid.connect.view.JsonEntityView;
import org.mitre.openid.connect.view.JsonErrorView;
import org.mitre.openid.connect.web.AuthenticationTimeStamper;
import org.mitre.springboot.config.annotation.EnableOpenIDConnectServer;
import org.mitre.uma.service.ResourceSetService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.OAuth2RequestValidator;
import org.springframework.security.oauth2.provider.TokenGranter;
import org.springframework.security.oauth2.provider.approval.UserApprovalHandler;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.error.DefaultWebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;
import org.springframework.security.oauth2.provider.error.OAuth2AuthenticationEntryPoint;
import org.springframework.security.oauth2.provider.error.WebResponseExceptionTranslator;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.servlet.view.BeanNameViewResolver;

import java.util.Arrays;

@Configuration
@ConditionalOnClass(EnableOpenIDConnectServer.class)
@ComponentScan(basePackages = {"org.mitre.springboot.config"})
@EnableWebSecurity
@EnableResourceServer
@EnableAuthorizationServer
@EnableConfigurationProperties()
@EnableGlobalMethodSecurity(prePostEnabled = true, proxyTargetClass = true)
@Order(101)
public class OpenIDConnectServerConfig{

    //TODO Configuration for ClientKeyPublisherMapping

    @Bean(name = "config")
    @ConfigurationProperties(prefix = "openid.connect.server")
    @ConditionalOnMissingBean(ConfigurationPropertiesBean.class)
    public ConfigurationPropertiesBean configurationPropertiesBean(){
        return new ConfigurationPropertiesBean();
    }

    @Bean
    public Http403ForbiddenEntryPoint http403ForbiddenEntryPoint(){
        return new Http403ForbiddenEntryPoint();
    }

    @Bean
    public WebResponseExceptionTranslator defaultWebResponseExceptionTranslator(){
        return new DefaultWebResponseExceptionTranslator();
    }

    @Bean
    public OAuth2AuthenticationEntryPoint oauth2AuthenticationEntryPoint(){
        final OAuth2AuthenticationEntryPoint entryPoint = new OAuth2AuthenticationEntryPoint();
        entryPoint.setRealmName("openidconnect");
        return entryPoint;
    }

    @Bean
    public OAuth2WebSecurityExpressionHandler oauthWebExpressionHandler(){
        return new OAuth2WebSecurityExpressionHandler();
    }

    /*
     * This is to allow resolution of the MitreID json endpoint view beans used in API and OIDC endpoints
     */
    @Bean
    public BeanNameViewResolver beanViewResolver(){
        final BeanNameViewResolver resolver = new BeanNameViewResolver();
        resolver.setOrder(0);
        return resolver;
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2AccessDeniedHandler.class)
    protected OAuth2AccessDeniedHandler oAuth2AccessDeniedHandler(){
        return new OAuth2AccessDeniedHandler();
    }

    /*
     * Enabled configuration for the package "org.mitre.openid.connect.web" 
     */
    @Configuration
    @Import(value = AuthenticationTimeStamper.class)
    public static class WebEndpointConfiguration{
    }

    /*
     * Specific configuration for "org.mitre.jwt.signer.service.impl"
     */

    @Configuration
    @Import(value = {ClientKeyCacheService.class, JWKSetCacheService.class, SymmetricKeyJWTValidatorCacheService.class})
    public static class JwtSignerServiceConfiguration{
    }

    /*
     * Override configuration for "org.mitre.oauth2.repository.impl"
     */

    @Bean
    @ConditionalOnMissingBean(AuthenticationHolderRepository.class)
    public AuthenticationHolderRepository jpaAuthenticationHolderRepository(){
        return new JpaAuthenticationHolderRepository();
    }

    @Bean
    @ConditionalOnMissingBean(AuthorizationCodeRepository.class)
    public AuthorizationCodeRepository jpaAuthorizationCodeRepository(){
        return new JpaAuthorizationCodeRepository();
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2ClientRepository.class)
    public OAuth2ClientRepository jpaOAuth2ClientRepository(){
        return new JpaOAuth2ClientRepository();
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2TokenRepository.class)
    public OAuth2TokenRepository jpaOAuth2TokenRepository(){
        return new JpaOAuth2TokenRepository();
    }

    @Bean
    @ConditionalOnMissingBean(SystemScopeRepository.class)
    public SystemScopeRepository jpaSystemScopeRepository(){
        return new JpaSystemScopeRepository();
    }

    /*
     * Override configuration for "org.mitre.oauth2.service.impl"
     */
    @Bean
    @ConditionalOnMissingBean(BlacklistAwareRedirectResolver.class)
    public BlacklistAwareRedirectResolver blacklistAwareRedirectResolver(){
        return new BlacklistAwareRedirectResolver();
    }

    @Bean
    @ConditionalOnMissingBean(IntrospectionResultAssembler.class)
    public IntrospectionResultAssembler defaultIntrospectionResultAssembler(){
        return new DefaultIntrospectionResultAssembler();
    }

    @Bean
    @ConditionalOnMissingBean(AuthorizationCodeServices.class)
    public DefaultOAuth2AuthorizationCodeService defaultOAuth2AuthorizationCodeService(){
        return new DefaultOAuth2AuthorizationCodeService();
    }

    @Bean
    @ConditionalOnMissingBean(ClientDetailsEntityService.class)
    public ClientDetailsEntityService defaultOAuth2ClientDetailsEntityService(){
        return new DefaultOAuth2ClientDetailsEntityService();
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2TokenEntityService.class)
    //Primary is necessary. Sometimes Spring Boot failed when is starting because there are 3 beans of type ResourceServerTokenServices.
    // We have to force this bean 
    @Primary
    public DefaultOAuth2ProviderTokenService defaultOAuth2ProviderTokenService(){
        return new DefaultOAuth2ProviderTokenService();
    }

    @Bean
    @ConditionalOnMissingBean(SystemScopeService.class)
    public SystemScopeService defaultSystemScopeService(){
        return new DefaultSystemScopeService();
    }

    @Bean
    @ConditionalOnMissingBean(name = "clientUserDetailsService")
    public UserDetailsService clientUserDetailsService(){
        return new DefaultClientUserDetailsService();
    }

    @Bean
    @ConditionalOnMissingBean(name = "uriEncodedClientUserDetailsService")
    public UserDetailsService uriEncodedClientUserDetailsService(){
        return new UriEncodedClientUserDetailsService();
    }

    @Bean
    @ConditionalOnMissingBean(name = "clientLogoLoadingService")
    public ClientLogoLoadingService clientLogoLoadingService(){
        return new InMemoryClientLogoLoadingService();
    }

    /*
     * Override configuration for "org.mitre.oauth2.token"
     */
    @Bean
    @Autowired
    @ConditionalOnMissingBean(name = "chainedTokenGranter")
    public TokenGranter chainedTokenGranter(final OAuth2TokenEntityService tokenServices,
            final ClientDetailsEntityService clientDetailsService, final OAuth2RequestFactory requestFactory){
        return new ChainedTokenGranter(tokenServices, clientDetailsService, requestFactory);
    }

    @Bean
    @Autowired
    @ConditionalOnMissingBean(name = "jwtAssertionValidator")
    public AssertionValidator jwtAssertionValidator(){
        return new NullAssertionValidator();
    }

    @Bean
    @Autowired
    @ConditionalOnMissingBean(name = "jwtAssertionTokenFactory")
    public AssertionOAuth2RequestFactory jwtAssertionTokenFactory(){
        return new DirectCopyRequestFactory();
    }

    @Bean
    @Autowired
    @ConditionalOnMissingBean(name = "clientAssertionValidator")
    @ConfigurationProperties(prefix = "openid.connect.endpoints.assertion.issuer")
    public AssertionValidator clientAssertionValidator(){
        final WhitelistedIssuerAssertionValidator assertionValidator = new WhitelistedIssuerAssertionValidator();

        return assertionValidator;
    }

    @Bean
    @Autowired
    @ConditionalOnMissingBean(name = "jwtAssertionTokenGranter")
    public TokenGranter jwtAssertionTokenGranter(final OAuth2TokenEntityService tokenServices,
            final ClientDetailsEntityService clientDetailsService, final OAuth2RequestFactory requestFactory){
        return new JWTAssertionTokenGranter(tokenServices, clientDetailsService, requestFactory);
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2RequestValidator.class)
    protected OAuth2RequestValidator requestValidator(){
        return new ScopeServiceAwareOAuth2RequestValidator();
    }

    /*
     * Endpoint configuration for "org.mitre.oauth2.view", "org.mitre.oauth2.web",
     */

    @Configuration
    @Import(value = {OAuthConfirmationController.class})
    public static class OAuthConfirmationControllerConfiguration{
    }

    /**
     * It is mandatory to use this CorsFilter because Cors with Spring MVC does not work.
     * The Spring-OAuth executes a security rule before than Cors with Spring MVC.
     *
     * See more https://github.com/spring-projects/spring-security-oauth/issues/330
     */
    @Bean
    @ConditionalOnMissingBean(name = "corsFilter")
    public Filter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("*");
        config.setAllowedHeaders(Arrays.asList("*"));
        config.setExposedHeaders(Arrays.asList("X-Requested-With","Origin","Content-Type", "Accept", "Authorization"));
        config.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE"));

        source.registerCorsConfiguration("/**", config);

        return new CorsFilter(source);

    }

    @Bean
    public FilterRegistrationBean corsFilterRegistration() {
        FilterRegistrationBean filterRegistrationBean = new FilterRegistrationBean(corsFilter());

        filterRegistrationBean.setOrder(FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER - 101);

        return filterRegistrationBean;
    }

    /*
     * Override configuration for "org.mitre.openid.connect.filter"
     */
    @Bean
    @Autowired
    @ConditionalOnMissingBean(name = "authRequestFilter")
    public Filter authRequestFilter(){
        return new AuthorizationRequestFilter();
    }

    /*
     * Override configuration "org.mitre.openid.connect.repository.impl"
     */

    @Bean
    @ConditionalOnMissingBean(AddressRepository.class)
    public AddressRepository jpaAddressRepository(){
        return new JpaAddressRepository();
    }

    @Bean
    @ConditionalOnMissingBean(ApprovedSiteRepository.class)
    public ApprovedSiteRepository jpaApprovedSiteRepository(){
        return new JpaApprovedSiteRepository();
    }

    @Bean
    @ConditionalOnMissingBean(BlacklistedSiteRepository.class)
    public BlacklistedSiteRepository jpaBlacklistedSiteRepository(){
        return new JpaBlacklistedSiteRepository();
    }

    @Bean
    @ConditionalOnMissingBean(PairwiseIdentifierRepository.class)
    public PairwiseIdentifierRepository jpaPairwiseIdentifierRepository(){
        return new JpaPairwiseIdentifierRepository();
    }

    @Bean
    @ConditionalOnMissingBean(UserInfoRepository.class)
    public UserInfoRepository jpaUserInfoRepository(){
        return new JpaUserInfoRepository();
    }

    @Bean
    @ConditionalOnMissingBean(WhitelistedSiteRepository.class)
    public WhitelistedSiteRepository jpaWhitelistedSiteRepository(){
        return new JpaWhitelistedSiteRepository();
    }

    /*
     * Override configuration "org.mitre.openid.connect.request"
     */

    @Bean
    @Autowired
    @ConditionalOnMissingBean(name = "connectOAuth2RequestFactory")
    public OAuth2RequestFactory connectOAuth2RequestFactory(final ClientDetailsEntityService clientDetailsService){
        return new ConnectOAuth2RequestFactory(clientDetailsService);
    }

    /*
     * Override configuration "org.mitre.openid.connect.service.impl"
     */

    @Bean
    @ConditionalOnMissingBean(ApprovedSiteService.class)
    public ApprovedSiteService defaultApprovedSiteService(){
        return new DefaultApprovedSiteService();
    }

    @Bean
    @ConditionalOnMissingBean(BlacklistedSiteService.class)
    public BlacklistedSiteService defaultBlacklistedSiteService(){
        return new DefaultBlacklistedSiteService();
    }

    @Bean
    @ConditionalOnMissingBean(OIDCTokenService.class)
    public OIDCTokenService defaultOIDCTokenService(){
        return new DefaultOIDCTokenService();
    }

    @Bean
    @ConditionalOnMissingBean(ScopeClaimTranslationService.class)
    public ScopeClaimTranslationService scopeClaimTranslator(){
        return new DefaultScopeClaimTranslationService();
    }

    @Bean
    @ConditionalOnMissingBean(StatsService.class)
    public StatsService defaultStatsService(){
        return new DefaultStatsService();
    }

    @Bean
    @ConditionalOnMissingBean(UserInfoService.class)
    public UserInfoService defaultUserInfoService(){
        return new DefaultUserInfoService();
    }

    @Bean
    @ConditionalOnMissingBean(WhitelistedSiteService.class)
    public WhitelistedSiteService defaultWhitelistedSiteService(){
        return new DefaultWhitelistedSiteService();
    }

    @Bean
    @ConditionalOnMissingBean(ResourceSetService.class)
    public ResourceSetService dummyResourceSetService(){
        return new DummyResourceSetService();
    }

    @Bean
    @ConditionalOnMissingBean(PairwiseIdentiferService.class)
    public PairwiseIdentiferService uuidPairwiseIdentiferService(){
        return new UUIDPairwiseIdentiferService();
    }

    /*
     * Override configuration "org.mitre.openid.connect.token"
     */

    /**
     * Due to required autowiring with no qualifier on
     * DefaultOAuth2ProviderTokenService of a TokenEnhancer instance, we can
     * only have one of these. If you have multiple token enhancers, you'll also
     * need to define your own DefaultOAuth2ProviderTokenService and inject a
     * TokenEnhancerChain with your list of TokenEnhancers
     */
    @Bean
    @ConditionalOnMissingBean(TokenEnhancer.class)
    public TokenEnhancer connectTokenEnhancer(){
        return new ConnectTokenEnhancer();
    }

    @Bean()
    @ConditionalOnMissingBean(UserApprovalHandler.class)
    public UserApprovalHandler tofuUserApprovalHandler(){
        return new TofuUserApprovalHandler();
    }

    /**
     * Configuration for common views in "org.mitre.openid.connect.view" used across most APIs and Endpoints
     */
    @Configuration
    @Import(value = {HttpCodeView.class, JsonEntityView.class, JsonErrorView.class})
    public static class OpenIDConnectCommonViewConfiguration{
    }

}
