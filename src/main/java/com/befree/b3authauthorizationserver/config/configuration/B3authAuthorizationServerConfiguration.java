package com.befree.b3authauthorizationserver.config.configuration;

import com.befree.b3authauthorizationserver.config.configurer.B3authAuthorizationServerConfigurer;
import com.befree.b3authauthorizationserver.settings.B3authAuthorizationServerSettings;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.HashSet;
import java.util.Set;

@Configuration(proxyBeanMethods = false)
public class B3authAuthorizationServerConfiguration {
    @Bean
    @Order(Integer.MIN_VALUE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        applyDefaultSecurity(http);
        return http.build();
    }

    private static void applyDefaultSecurity(HttpSecurity http) throws Exception {
        B3authAuthorizationServerConfigurer authorizationServerConfigurer = new B3authAuthorizationServerConfigurer();
        RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
        http.securityMatcher(endpointsMatcher).authorizeHttpRequests((authorize) -> {
            ((AuthorizeHttpRequestsConfigurer.AuthorizedUrl)authorize.anyRequest()).authenticated();
        }).csrf((csrf) -> {
            csrf.ignoringRequestMatchers(endpointsMatcher);
        }).apply(authorizationServerConfigurer);
    }

    @Bean
    RegisterMissingBeanPostProcessor registerMissingBeanPostProcessor() {
        RegisterMissingBeanPostProcessor postProcessor = new RegisterMissingBeanPostProcessor();
        postProcessor.addBeanDefinition(B3authAuthorizationServerSettings.class, () -> B3authAuthorizationServerSettings.builder().build());
        return postProcessor;
    }
}
