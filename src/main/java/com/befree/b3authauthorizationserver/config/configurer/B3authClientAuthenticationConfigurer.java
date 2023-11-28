package com.befree.b3authauthorizationserver.config.configurer;

import com.befree.b3authauthorizationserver.authentication.*;
import com.befree.b3authauthorizationserver.config.configuration.B3authConfigurationLoader;
import com.befree.b3authauthorizationserver.settings.B3authAuthorizationServerSettings;
import com.befree.b3authauthorizationserver.web.B3authClientAuthenticationEndpointFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class B3authClientAuthenticationConfigurer extends AbstractB3authConfigurer {
    private final List<AuthenticationConverter> authorizationRequestConverters = new ArrayList<>();
    private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

    private Consumer<List<AuthenticationConverter>> authorizationRequestConvertersConsumer = (authorizationRequestConverters) -> {};
    private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {};

    B3authClientAuthenticationConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
        super(objectPostProcessor);
    }

    @Override
    void init(HttpSecurity httpSecurity) {
        B3authAuthorizationServerSettings authorizationServerSettings = B3authConfigurationLoader.getAuthorizationServerSettings(httpSecurity);

        List<AuthenticationProvider> authenticationProviders = createDefaultAuthenticationProviders(httpSecurity);
        if (!this.authenticationProviders.isEmpty()) {
            authenticationProviders.addAll(0, this.authenticationProviders);
        }
        this.authenticationProvidersConsumer.accept(authenticationProviders);
        authenticationProviders.forEach(authenticationProvider ->
                httpSecurity.authenticationProvider(postProcess(authenticationProvider)));
    }

    @Override
    void configure(HttpSecurity httpSecurity) {
        AuthenticationManager authenticationManager = httpSecurity.getSharedObject(AuthenticationManager.class);
        B3authAuthorizationServerSettings authorizationServerSettings = B3authConfigurationLoader.getAuthorizationServerSettings(httpSecurity);

        B3authClientAuthenticationEndpointFilter clientAuthenticationEndpointFilter =
                new B3authClientAuthenticationEndpointFilter(
                        authenticationManager,
                        new DelegatingAuthenticationConverter(authorizationRequestConverters),
                        B3authConfigurationLoader.getSessionService(httpSecurity),
                        B3authConfigurationLoader.getJwtGenerator(httpSecurity),
                        B3authConfigurationLoader.getSessionGenerator(httpSecurity));

        List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();

        System.out.println(authenticationConverters.size());

        if (!this.authorizationRequestConverters.isEmpty()) {
            authenticationConverters.addAll(0, this.authorizationRequestConverters);
        }

        this.authorizationRequestConvertersConsumer.accept(authenticationConverters);

        System.out.println(authenticationConverters.size());

        clientAuthenticationEndpointFilter.setAuthenticationConverter(
                new DelegatingAuthenticationConverter(authenticationConverters));

        httpSecurity.addFilterBefore(postProcess(clientAuthenticationEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

    }

    private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
        List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

        authenticationConverters.add(new B3authDefaultClientAuthenticationConverter());

        System.out.println(authenticationConverters.size());

        return authenticationConverters;
    }

    private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

        B3authClientAuthenticationProvider userAuthenticationProvider =
                new B3authClientAuthenticationProvider(
                        B3authConfigurationLoader.getClientService(httpSecurity),
                        B3authConfigurationLoader.getPasswordEncoder(httpSecurity));

        authenticationProviders.add(userAuthenticationProvider);

        return authenticationProviders;
    }
}
