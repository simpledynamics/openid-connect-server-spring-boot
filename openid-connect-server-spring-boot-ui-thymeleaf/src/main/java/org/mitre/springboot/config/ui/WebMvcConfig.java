package org.mitre.springboot.config.ui;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.mitre.openid.connect.config.JsonMessageSource;
import org.mitre.openid.connect.config.UIConfiguration;
import org.mitre.openid.connect.web.RootController;
import org.mitre.openid.connect.web.ServerConfigInterceptor;
import org.mitre.openid.connect.web.UserInfoInterceptor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.Resource;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.ResourceHandlerRegistry;
import org.springframework.web.servlet.config.annotation.ViewControllerRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

@Configuration
@EnableWebMvc
public class WebMvcConfig extends WebMvcConfigurerAdapter{

    @Bean
    @ConditionalOnMissingBean(UserInfoInterceptor.class)
    public UserInfoInterceptor getUserInfoInterceptor(){
        return new UserInfoInterceptor();
    }

    @Bean
    @ConditionalOnMissingBean(ServerConfigInterceptor.class)
    public ServerConfigInterceptor getServerConfigInterceptor(){
        return new ServerConfigInterceptor();
    }

    @Bean
    @ConditionalOnMissingBean(JsonMessageSource.class)
    @ConfigurationProperties(prefix = "openid.connect.jsonMessageSource")
    public JsonMessageSource messageSource(@Value("classpath:/static/resources/js/locale/")
    final Resource baseDirectory, @Value("true")
    final Boolean useCodeAsDefaultMessage){
        final JsonMessageSource jsonMessageSource = new JsonMessageSource();
        jsonMessageSource.setBaseDirectory(baseDirectory);
        jsonMessageSource.setUseCodeAsDefaultMessage(useCodeAsDefaultMessage);
        return jsonMessageSource;
    }

    @Bean(name = "uiConfiguration")
    @ConfigurationProperties(prefix = "openid.connect.server.ui")
    @ConditionalOnMissingBean(UIConfiguration.class)
    public UIConfiguration configurationPropertiesBean(){
        final UIConfiguration uiConfiguration = new UIConfiguration();
     // @formatter:off
        final Set<String> jsResources = new HashSet<String>(
                Arrays.asList(
                        "resources/js/client.js",
                        "resources/js/grant.js",
                        "resources/js/scope.js",
                        "resources/js/whitelist.js",
                        "resources/js/dynreg.js",
                        "resources/js/rsreg.js",
                        "resources/js/token.js",
                        "resources/js/blacklist.js",
                        "resources/js/profile.js"
                        ));
     // @formatter:on

        uiConfiguration.setJsFiles(jsResources);
        return uiConfiguration;
    }

    @Override
    public void addInterceptors(final InterceptorRegistry registry){
        registry.addInterceptor(getUserInfoInterceptor());
        registry.addInterceptor(getServerConfigInterceptor());
    }

    @Override
    public void addViewControllers(final ViewControllerRegistry registry){
        registry.addViewController("/login").setViewName("login");
    }

    @Override
    public void addResourceHandlers(final ResourceHandlerRegistry registry){
        registry.addResourceHandler("/resources/**").addResourceLocations("classpath:/static/resources/");
    }

    @Configuration
    @Import(RootController.class)
    public static class RootControllerConfiguration{
    }

}
