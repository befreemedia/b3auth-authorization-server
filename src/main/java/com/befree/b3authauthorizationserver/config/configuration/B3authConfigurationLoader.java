package com.befree.b3authauthorizationserver.config.configuration;

import com.befree.b3authauthorizationserver.B3authAuthenticationAttemptService;
import com.befree.b3authauthorizationserver.B3authSessionGenerator;
import com.befree.b3authauthorizationserver.B3authSessionService;
import com.befree.b3authauthorizationserver.B3authUserService;
import com.befree.b3authauthorizationserver.jwt.JwtGenerator;
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

    public static B3authSessionService getSessionService(HttpSecurity httpSecurity) {
        B3authSessionService sessionService = httpSecurity.getSharedObject(B3authSessionService.class);

        if (sessionService == null) {

            ResolvableType type = ResolvableType.forClass(B3authSessionService.class);

            sessionService = getOptionalBean(httpSecurity, type);

            if (sessionService != null) {
                httpSecurity.setSharedObject(B3authSessionService.class, sessionService);
            } else {
                throw new RuntimeException("B3authSessionService bean must be specified.");
            }
        }

        return sessionService;
    }

    public static B3authUserService getUserService(HttpSecurity httpSecurity) {
        B3authUserService userService = httpSecurity.getSharedObject(B3authUserService.class);
        if (userService == null) {

            ResolvableType type = ResolvableType.forClass(B3authUserService.class);

            userService = getOptionalBean(httpSecurity, B3authUserService.class);

            if (userService != null) {
                httpSecurity.setSharedObject(B3authUserService.class, userService);
            } else {
                throw new RuntimeException("B3authUserService bean must be specified.");
            }

        }
        return userService;
    }

    public static B3authAuthenticationAttemptService getAuthenticationAttemptService(HttpSecurity httpSecurity) {
        B3authAuthenticationAttemptService authenticationAttemptService = httpSecurity.getSharedObject(B3authAuthenticationAttemptService.class);
        if (authenticationAttemptService == null) {

            ResolvableType type = ResolvableType.forClass(B3authAuthenticationAttemptService.class);

            authenticationAttemptService = getOptionalBean(httpSecurity, B3authAuthenticationAttemptService.class);

            if (authenticationAttemptService != null) {
                httpSecurity.setSharedObject(B3authAuthenticationAttemptService.class, authenticationAttemptService);
            } else {
                throw new RuntimeException("B3authAuthenticationAttemptService bean must be specified.");
            }

        }
        return authenticationAttemptService;
    }

    public static B3authSessionGenerator getSessionGenerator(HttpSecurity httpSecurity) {
        B3authSessionGenerator sessionGenerator = httpSecurity.getSharedObject(B3authSessionGenerator.class);
        if (sessionGenerator == null) {

            ResolvableType type = ResolvableType.forClass(B3authSessionGenerator.class);

            sessionGenerator = getOptionalBean(httpSecurity, B3authSessionGenerator.class);

            if (sessionGenerator != null) {
                httpSecurity.setSharedObject(B3authSessionGenerator.class, sessionGenerator);
            } else {
                throw new RuntimeException("B3authSessionGenerator bean must be specified.");
            }

        }
        return sessionGenerator;
    }

    public static JwtGenerator getJwtGenerator(HttpSecurity httpSecurity) {
        JwtGenerator jwtGenerator = httpSecurity.getSharedObject(JwtGenerator.class);

        if (jwtGenerator == null) {

            JWKSource<SecurityContext> jwkSource = getJwkSource(httpSecurity);

            if (jwkSource != null) {
                jwtGenerator = new JwtGenerator(jwkSource);
                httpSecurity.setSharedObject(JwtGenerator.class, jwtGenerator);
            }
        }

        return jwtGenerator;
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
