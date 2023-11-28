package com.befree.b3authauthorizationserver.config.configurer;

import com.befree.b3authauthorizationserver.authentication.B3authDefaultUserAuthenticationConverter;
import com.befree.b3authauthorizationserver.authentication.B3authUserAuthenticationProvider;
import com.befree.b3authauthorizationserver.authentication.DelegatingAuthenticationConverter;
import com.befree.b3authauthorizationserver.config.configuration.B3authConfigurationLoader;
import com.befree.b3authauthorizationserver.settings.B3authAuthorizationServerSettings;
import com.befree.b3authauthorizationserver.web.B3authUserAuthenticationAttemptEndpointFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

public class B3authUserAuthenticationAttemptConfigurer extends AbstractB3authConfigurer {
    private final List<AuthenticationConverter> authorizationRequestConverters = new ArrayList<>();
    private final List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

    private Consumer<List<AuthenticationConverter>> authorizationRequestConvertersConsumer = (authorizationRequestConverters) -> {};
    private Consumer<List<AuthenticationProvider>> authenticationProvidersConsumer = (authenticationProviders) -> {};

    B3authUserAuthenticationAttemptConfigurer(ObjectPostProcessor<Object> objectPostProcessor) {
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

        B3authUserAuthenticationAttemptEndpointFilter userAuthenticationAttemptEndpointFilter =
                new B3authUserAuthenticationAttemptEndpointFilter(
                        authenticationManager,
                        new DelegatingAuthenticationConverter(authorizationRequestConverters));

        List<AuthenticationConverter> authenticationConverters = createDefaultAuthenticationConverters();

        if (!this.authorizationRequestConverters.isEmpty()) {
            authenticationConverters.addAll(0, this.authorizationRequestConverters);
        }
        this.authorizationRequestConvertersConsumer.accept(authenticationConverters);

        userAuthenticationAttemptEndpointFilter.setAuthenticationConverter(
                new DelegatingAuthenticationConverter(authenticationConverters));

        httpSecurity.addFilterBefore(postProcess(userAuthenticationAttemptEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);

    }

    private static List<AuthenticationConverter> createDefaultAuthenticationConverters() {
        List<AuthenticationConverter> authenticationConverters = new ArrayList<>();

        authenticationConverters.add(new B3authDefaultUserAuthenticationConverter());

        return authenticationConverters;
    }

    private List<AuthenticationProvider> createDefaultAuthenticationProviders(HttpSecurity httpSecurity) {
        List<AuthenticationProvider> authenticationProviders = new ArrayList<>();

        B3authUserAuthenticationProvider userAuthenticationProvider =
                new B3authUserAuthenticationProvider(
                        B3authConfigurationLoader.getUserService(httpSecurity),
                        B3authConfigurationLoader.getAuthenticationAttemptService(httpSecurity));

        authenticationProviders.add(userAuthenticationProvider);

        return authenticationProviders;
    }
}
