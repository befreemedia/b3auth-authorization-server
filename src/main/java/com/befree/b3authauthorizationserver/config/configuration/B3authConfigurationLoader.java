package com.befree.b3authauthorizationserver.config.configuration;

import com.befree.b3authauthorizationserver.B3authTokenService;
import com.befree.b3authauthorizationserver.settings.B3authAuthorizationServerSettings;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.BeanFactoryUtils;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.NoUniqueBeanDefinitionException;
import org.springframework.context.ApplicationContext;
import org.springframework.core.ResolvableType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.StringUtils;

import java.util.Map;

public final class B3authConfigurationLoader {

    public static B3authAuthorizationServerSettings getAuthorizationServerSettings(HttpSecurity httpSecurity) {
        B3authAuthorizationServerSettings authorizationServerSettings = httpSecurity.getSharedObject(B3authAuthorizationServerSettings.class);
        if (authorizationServerSettings == null) {
            authorizationServerSettings = getBean(httpSecurity, B3authAuthorizationServerSettings.class);
            httpSecurity.setSharedObject(B3authAuthorizationServerSettings.class, authorizationServerSettings);
        }

        return authorizationServerSettings;
    }

    public static JWKSource<SecurityContext> getJwkSource(HttpSecurity httpSecurity) {
        JWKSource<SecurityContext> jwkSource = httpSecurity.getSharedObject(JWKSource.class);

        if (jwkSource == null) {
            ResolvableType type = ResolvableType.forClassWithGenerics(JWKSource.class, SecurityContext.class);

            jwkSource = getOptionalBean(httpSecurity, type);

            if (jwkSource != null) {
                httpSecurity.setSharedObject(JWKSource.class, jwkSource);
            }
        }

        return jwkSource;
    }

    public static B3authTokenService getB3authTokenService(HttpSecurity httpSecurity) {
        B3authTokenService tokenService = httpSecurity.getSharedObject(B3authTokenService.class);

        if (tokenService == null) {

            ResolvableType type = ResolvableType.forClass(B3authTokenService.class);

            tokenService = getOptionalBean(httpSecurity, type);

            if (tokenService != null) {
                httpSecurity.setSharedObject(B3authTokenService.class, tokenService);
            }
        }

        return tokenService;
    }

    public static <T> T getBean(HttpSecurity httpSecurity, Class<T> type) {
        return (httpSecurity.getSharedObject(ApplicationContext.class)).getBean(type);
    }

    public static <T> T getOptionalBean(HttpSecurity httpSecurity, Class<T> type) {
        Map<String, T> beansMap = BeanFactoryUtils.beansOfTypeIncludingAncestors((ListableBeanFactory)httpSecurity.getSharedObject(ApplicationContext.class), type);
        if (beansMap.size() > 1) {
            int var10003 = beansMap.size();
            String var10004 = type.getName();
            throw new NoUniqueBeanDefinitionException(type, var10003, "Expected single matching bean of type '" + var10004 + "' but found " + beansMap.size() + ": " + StringUtils.collectionToCommaDelimitedString(beansMap.keySet()));
        } else {
            return !beansMap.isEmpty() ? beansMap.values().iterator().next() : null;
        }
    }

    public static <T> T getOptionalBean(HttpSecurity httpSecurity, ResolvableType type) {
        ApplicationContext context = httpSecurity.getSharedObject(ApplicationContext.class);
        String[] names = context.getBeanNamesForType(type);
        if (names.length > 1) {
            throw new NoUniqueBeanDefinitionException(type, names);
        } else {
            return names.length == 1 ? (T) context.getBean(names[0]) : null;
        }
    }
}
