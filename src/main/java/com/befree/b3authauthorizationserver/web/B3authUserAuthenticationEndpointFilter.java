package com.befree.b3authauthorizationserver.web;

import com.befree.b3authauthorizationserver.*;
import com.befree.b3authauthorizationserver.config.configuration.B3authEndpointsList;
import com.befree.b3authauthorizationserver.jwt.*;
import com.nimbusds.jose.shaded.gson.JsonObject;
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
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URL;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

public class B3authUserAuthenticationEndpointFilter extends OncePerRequestFilter {
    private final RequestMatcher requestMatcher;
    private final AuthenticationManager authenticationManager;
    private AuthenticationConverter authenticationConverter;
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;
    private final JwtGenerator jwtGenerator;
    private final B3authSessionGenerator b3authSessionGenerator;

    private final B3authSessionService sessionService;
    private final Long AUTHORIZATION_TOKEN_SECONDS_VALID = 600L;
    // todo temporary unchangeable, will be done from properties
    private final Long REFRESH_TOKEN_SECONDS_VALID = 5184000L;
    private final String ISSUER = "https://domain.com";


    public B3authUserAuthenticationEndpointFilter(AuthenticationManager authenticationManager,
                                                  AuthenticationConverter authenticationConverter,
                                                  B3authSessionService sessionService,
                                                  JwtGenerator jwtGenerator,
                                                  B3authSessionGenerator b3authSessionGenerator) {
        this.b3authSessionGenerator = b3authSessionGenerator;
        Assert.notNull(authenticationManager, "authentication manager can't be null");
        Assert.notNull(authenticationConverter, "authentication converter can't be null");
        Assert.notNull(jwtGenerator, "jwt generator must not be null");
        Assert.notNull(sessionService, "token service can't be null");

        this.authenticationManager = authenticationManager;
        this.requestMatcher = new OrRequestMatcher(new AntPathRequestMatcher(B3authEndpointsList.USER_AUTHENTICATION),
                new AntPathRequestMatcher("/api" + B3authEndpointsList.USER_AUTHENTICATION));
        this.authenticationConverter = authenticationConverter;
        this.authenticationDetailsSource = new WebAuthenticationDetailsSource();
        this.jwtGenerator = jwtGenerator;
        this.sessionService = sessionService;
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
                ((AbstractAuthenticationToken) authentication)
                        .setDetails(this.authenticationDetailsSource.buildDetails(request));
            }

            Authentication authenticationResult = this.authenticationManager.authenticate(authentication);

            if (!authenticationResult.isAuthenticated()) {
                filterChain.doFilter(request, response);
                return;
            }

            if (authenticationResult instanceof B3authAuthorizationToken) {
                this.setAuthenticationSuccess(request, response, authenticationResult);
            } else {
                throw new B3authAuthenticationException("Server authentication error.", "Wrong server configuration",
                        B3authAuthorizationServerExceptionCode.B5001);
            }
        } catch(AuthenticationException e) {
            this.setAuthenticationError(request, response, e);
        }
    }
    
    private void setAuthenticationSuccess(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                          @NonNull Authentication authentication) throws IOException {
        try {
            if (authentication instanceof B3authAuthorizationToken b3authAuthorizationToken) {
                var json = new JsonObject();

                LocalDateTime now = LocalDateTime.now();

                Map<String, Object> claims = new HashMap<>();
                claims.put("initialized", b3authAuthorizationToken.isUserInitialized());

                URL issuer = new URL(ISSUER);


                Jwt authorizationToken = jwtGenerator.generate(b3authAuthorizationToken.getSessionId(),
                        B3authTokenType.AUTHORIZATION_TOKEN, AUTHORIZATION_TOKEN_SECONDS_VALID, now, claims,
                        b3authAuthorizationToken.getUserId(), new ArrayList<>(),
                        b3authAuthorizationToken.getAuthorities(), issuer);

                Jwt refreshToken = jwtGenerator.generate(b3authAuthorizationToken.getSessionId(),
                        B3authTokenType.REFRESH_TOKEN, REFRESH_TOKEN_SECONDS_VALID, now, claims,
                        b3authAuthorizationToken.getUserId(), new ArrayList<>(),
                        b3authAuthorizationToken.getAuthorities(), issuer);

                B3authSession session = b3authSessionGenerator.generate(authorizationToken, refreshToken, b3authAuthorizationToken);


                sessionService.save(session);

                json.addProperty("access_token", "Bearer " + authorizationToken.getValue());

                json.addProperty("refresh_token", "Bearer " + refreshToken.getValue());

                json.addProperty("initialized",  b3authAuthorizationToken.isUserInitialized());

                var stringValue = json.toString();

                response.setStatus(200);
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.setContentLength(stringValue.getBytes().length);
                response.getWriter().write(stringValue);
            } else {
                throw new B3authAuthenticationException("Server authentication error.", "Wrong server configuration",
                        B3authAuthorizationServerExceptionCode.B5001);
            }
        } catch (AuthenticationException e) {
            this.setAuthenticationError(request, response, e);
        }
    }

    private void setAuthenticationError(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                        AuthenticationException authenticationException) throws IOException {
        if(authenticationException instanceof B3authAuthenticationException exception) {
            var json = new JsonObject();

            json.addProperty("error_code", exception.getErrorCode().toString());
            json.addProperty("error_name", exception.getErrorCode().getErrorName());
            json.addProperty("error_description", exception.getDescription());

            var stringValue = json.toString();

            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setContentLength(stringValue.getBytes().length);
            response.getWriter().write(stringValue);
        } else {
            response.sendError(HttpStatus.INTERNAL_SERVER_ERROR.value(), authenticationException.toString());
        }
    }

    public void setAuthenticationConverter(AuthenticationConverter authenticationConverter) {
        Assert.notNull(authenticationConverter, "authenticationConverter cannot be null");
        this.authenticationConverter = authenticationConverter;
    }
}
