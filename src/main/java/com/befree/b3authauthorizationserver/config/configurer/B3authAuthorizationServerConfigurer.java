package com.befree.b3authauthorizationserver.config.configurer;

import com.befree.b3authauthorizationserver.config.configuration.B3authConfigurationLoader;
import com.befree.b3authauthorizationserver.config.configuration.B3authEndpointsList;
import com.befree.b3authauthorizationserver.settings.B3authAuthorizationServerSettings;
import com.befree.b3authauthorizationserver.web.NimbusJwkEndpointFilter;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

import java.lang.reflect.Field;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

public class B3authAuthorizationServerConfigurer extends AbstractHttpConfigurer<B3authAuthorizationServerConfigurer, HttpSecurity> {
    private RequestMatcher endpointsMatcher;

    public RequestMatcher getEndpointsMatcher() {
        return (request) -> {
            return this.endpointsMatcher.matches(request);
        };
    }


    @Override
    public void init(HttpSecurity httpSecurity) throws Exception {
        B3authAuthorizationServerSettings authorizationServerSettings = B3authConfigurationLoader.getAuthorizationServerSettings(httpSecurity);
        validateAuthorizationServerSettings(authorizationServerSettings);

        List<RequestMatcher> requestMatchers = new ArrayList<RequestMatcher>();
        for (Field field : B3authEndpointsList.class.getDeclaredFields()) {
            if(field.getType() == String.class) {
                String value = (String) field.get(field.getType());
                requestMatchers.add(new AntPathRequestMatcher(value));
            }
        }

        this.endpointsMatcher = new OrRequestMatcher(requestMatchers);

        ExceptionHandlingConfigurer<HttpSecurity> exceptionHandling = (ExceptionHandlingConfigurer) httpSecurity.getConfigurer(ExceptionHandlingConfigurer.class);
        if (exceptionHandling != null) {
            exceptionHandling.defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), new OrRequestMatcher(getRequestMatchers(B3authEndpointsList.CLIENT_AUTHENTICATION, B3authEndpointsList.USER_AUTHENTICATION, B3authEndpointsList.CLIENT_TOKEN_REVOCATION, B3authEndpointsList.USER_TOKEN_REFRESH)));
        }
    }

    public void configure(HttpSecurity httpSecurity) {
        B3authAuthorizationServerSettings authorizationServerSettings = B3authConfigurationLoader.getAuthorizationServerSettings(httpSecurity);
        B3authAuthorizationServerContextFilter authorizationServerContextFilter = new B3authAuthorizationServerContextFilter(authorizationServerSettings);
        httpSecurity.addFilterAfter(this.postProcess(authorizationServerContextFilter), SecurityContextHolderFilter.class);
        JWKSource<SecurityContext> jwkSource = B3authConfigurationLoader.getJwkSource(httpSecurity);
        if (jwkSource != null) {
            NimbusJwkEndpointFilter jwkSetEndpointFilter = new NimbusJwkEndpointFilter(jwkSource);
            httpSecurity.addFilterBefore(this.postProcess(jwkSetEndpointFilter), AbstractPreAuthenticatedProcessingFilter.class);
        }

    }

    private RequestMatcher getRequestMatcher(String endpointName) {
        Assert.hasText(endpointName, "endpoint can't be empty");
        return new AntPathRequestMatcher(endpointName);
    }

    private RequestMatcher[] getRequestMatchers(String ...endpointNames) {
        List<RequestMatcher> matchers = new ArrayList<>();

        for (String endpointName : endpointNames) {
            Assert.hasText(endpointName, "endpoint name cannot be empty");
            matchers.add(new AntPathRequestMatcher(endpointName));
        }

        Assert.isTrue(!matchers.isEmpty(), "you have to provide some endpoint names");

        return matchers.toArray(new RequestMatcher[0]);
    }

    private static void validateAuthorizationServerSettings(B3authAuthorizationServerSettings authorizationServerSettings) {
        if (authorizationServerSettings.getIssuer() != null) {
            URI issuerUri;
            try {
                issuerUri = new URI(authorizationServerSettings.getIssuer());
                issuerUri.toURL();
            } catch (Exception var3) {
                throw new IllegalArgumentException("issuer must be a valid URL", var3);
            }

            if (issuerUri.getQuery() != null || issuerUri.getFragment() != null) {
                throw new IllegalArgumentException("issuer cannot contain query or fragment component");
            }
        }
    }
}
