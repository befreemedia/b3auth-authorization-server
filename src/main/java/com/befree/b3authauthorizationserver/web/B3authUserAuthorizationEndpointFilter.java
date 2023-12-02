package com.befree.b3authauthorizationserver.web;

import com.befree.b3authauthorizationserver.B3authAuthenticationException;
import com.befree.b3authauthorizationserver.B3authAuthorizationServerExceptionCode;
import com.befree.b3authauthorizationserver.B3authAuthorizationToken;
import com.befree.b3authauthorizationserver.jwt.JwtGenerator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class B3authUserAuthorizationEndpointFilter extends OncePerRequestFilter {
    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private SecurityContextRepository securityContextRepository = new RequestAttributeSecurityContextRepository();
    private final AuthenticationDetailsSource<HttpServletRequest, ?> authenticationDetailsSource;
    private AuthenticationManager authenticationManager;
    private AuthenticationConverter authenticationConverter;

    public B3authUserAuthorizationEndpointFilter(AuthenticationConverter authenticationConverter,
                                                 AuthenticationManager authenticationManager) {
        this.authenticationDetailsSource =  new WebAuthenticationDetailsSource();
        this.authenticationConverter = authenticationConverter;
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        LoggerFactory.getLogger(B3authUserAuthorizationEndpointFilter.class).debug("started");
        System.out.println("started");

        try {
            LoggerFactory.getLogger(B3authUserAuthorizationEndpointFilter.class).debug("converting");
            Authentication authentication = authenticationConverter.convert(request);
            LoggerFactory.getLogger(B3authUserAuthorizationEndpointFilter.class).debug("converted");
            if (authentication instanceof AbstractAuthenticationToken) {
                ((AbstractAuthenticationToken) authentication)
                        .setDetails(this.authenticationDetailsSource.buildDetails(request));
            } else {
                throw new B3authAuthenticationException("Convertion failed.", "tb",
                        B3authAuthorizationServerExceptionCode.B4004);
            }

            LoggerFactory.getLogger(B3authUserAuthorizationEndpointFilter.class).debug("details set");

            Authentication authenticationResult = this.authenticationManager.authenticate(authentication);

            LoggerFactory.getLogger(B3authUserAuthorizationEndpointFilter.class).debug("manager success");

            if (authenticationResult instanceof B3authAuthorizationToken) {

                SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
                context.setAuthentication(authenticationResult);
                LoggerFactory.getLogger(B3authUserAuthorizationEndpointFilter.class).debug("set authentication");
                this.securityContextHolderStrategy.setContext(context);
                this.securityContextRepository.saveContext(context, request, response);

                SecurityContextHolder.getContext().setAuthentication(authenticationResult);

                LoggerFactory.getLogger(B3authUserAuthorizationEndpointFilter.class).debug("all succeed");

                filterChain.doFilter(request, response);

            } else {
                LoggerFactory.getLogger(B3authUserAuthorizationEndpointFilter.class).debug("wrong token");
                throw new B3authAuthenticationException("Server authentication error.", "Wrong server configuration",
                        B3authAuthorizationServerExceptionCode.B5001);
            }
        } catch (AuthenticationException authenticationException) {
            this.securityContextHolderStrategy.clearContext();
            LoggerFactory.getLogger(B3authUserAuthorizationEndpointFilter.class).error(authenticationException.getMessage());
        }
    }
}
