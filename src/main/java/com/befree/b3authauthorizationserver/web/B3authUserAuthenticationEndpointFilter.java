package com.befree.b3authauthorizationserver.web;

import com.befree.b3authauthorizationserver.B3authAuthenticationException;
import com.befree.b3authauthorizationserver.B3authAuthenticationToken;
import com.befree.b3authauthorizationserver.B3authAuthorizationServerExceptionCode.*;
import com.befree.b3authauthorizationserver.B3authTokenService;
import com.befree.b3authauthorizationserver.config.configuration.B3authEndpointsList;
import com.befree.b3authauthorizationserver.jwt.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.shaded.gson.JsonObject;
import com.nimbusds.jose.util.ByteUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class B3authUserAuthenticationEndpointFilter extends OncePerRequestFilter {
    private final RequestMatcher requestMatcher;
    private final AuthenticationManager authenticationManager;
    private final AuthenticationConverter authenticationConverter;
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;
    private final JwtGenerator jwtGenerator;

    private final B3authTokenService tokenService;
    private final Long AUTHORIZATION_TOKEN_SECONDS_VALID = 600L;
    private final Long REFRESH_TOKEN_SECONDS_VALID = 5184000L;
    public B3authUserAuthenticationEndpointFilter(AuthenticationManager authenticationManager,
                                                  AuthenticationConverter authenticationConverter,
                                                  B3authTokenService tokenService,
                                                  JwtGenerator jwtGenerator) {

        Assert.notNull(authenticationManager, "authentication manager can't be null");
        Assert.notNull(authenticationConverter, "authentication converter can't be null");
        Assert.notNull(jwtGenerator, "jwt generator must not be null");
        Assert.notNull(tokenService, "token service can't be null");

        this.authenticationManager = authenticationManager;
        this.requestMatcher = new AntPathRequestMatcher(B3authEndpointsList.USER_AUTHENTICATION);
        this.authenticationConverter = authenticationConverter;
        this.authenticationDetailsSource = new WebAuthenticationDetailsSource();
        this.jwtGenerator = jwtGenerator;
        this.tokenService = tokenService;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
        try {
            if (!requestMatcher.matches(request)) {
                filterChain.doFilter(request, response);
                return;
            }

            Authentication authentication = authenticationConverter.convert(request);

            if (authentication instanceof AbstractAuthenticationToken) {
                ((AbstractAuthenticationToken) authentication).setDetails(this.authenticationDetailsSource.buildDetails(request));
            }

            Authentication authenticationResult = this.authenticationManager.authenticate(authentication);
            if (!authenticationResult.isAuthenticated()) {
                filterChain.doFilter(request, response);
                return;
            }

            if (authenticationResult instanceof B3authAuthenticationToken) {
                filterChain.doFilter(request, response);
                this.setAuthenticationSuccess(request, response, authenticationResult);
            } else {
                throw new B3authAuthenticationException("Server authentication error.", B3authAuthenticationEndpointExceptionCode.B5001, "Wrong server configuration");
            }

            filterChain.doFilter(request, response);
        } catch(AuthenticationException e) {
            this.setAuthenticationError(request, response, e);
        }
    }
    
    private void setAuthenticationSuccess(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull Authentication authentication) throws IOException {
        try {
            if (authentication instanceof B3authAuthenticationToken authenticationToken) {
                var json = new JsonObject();

                LocalDateTime now = LocalDateTime.now();

                Map<String, Object> claims = new HashMap<>();

                URL issuer = new URL("localhost");

                Jwt authorizationToken = jwtGenerator.generate(B3authTokenType.AUTHORIZATION_TOKEN, AUTHORIZATION_TOKEN_SECONDS_VALID, now, claims, authenticationToken.getPrincipalId(), new ArrayList<>(), authenticationToken.getAuthorities(), issuer);

                tokenService.save(authorizationToken);

                json.addProperty("authorization_token", authorizationToken.getValue());

                json.addProperty("token_type", "Bearer");

                var stringValue = json.toString();

                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setContentLength(stringValue.getBytes().length);
                response.getWriter().write(stringValue);
            } else {
                throw new B3authAuthenticationException("Server authentication error.", B3authAuthenticationEndpointExceptionCode.B5001, "Wrong server configuration");
            }
        } catch (AuthenticationException e) {
            this.setAuthenticationError(request, response, e);
        }
    }

    private void setAuthenticationError(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response, AuthenticationException authenticationException) throws IOException {
        if(authenticationException instanceof B3authAuthenticationException exception) {
            var json = new JsonObject();

            json.addProperty("error_code", exception.getErrorCode());
            json.addProperty("error_description", exception.getDescription());

            var stringValue = json.toString();

            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setContentLength(stringValue.getBytes().length);
            response.getWriter().write(stringValue);
        } else {
            response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), authenticationException.toString());
        }
    }
}
