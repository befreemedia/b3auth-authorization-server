package com.befree.b3authauthorizationserver.web;

import com.befree.b3authauthorizationserver.B3authAuthenticationException;
import com.befree.b3authauthorizationserver.B3authAuthorizationServerExceptionCode;
import com.befree.b3authauthorizationserver.B3authAuthorizationToken;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
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
        Authentication authentication = authenticationConverter.convert(request);

        if (authentication instanceof AbstractAuthenticationToken) {
            ((AbstractAuthenticationToken) authentication)
                    .setDetails(this.authenticationDetailsSource.buildDetails(request));
        }

        Authentication authenticationResult = this.authenticationManager.authenticate(authentication);

        if (authenticationResult instanceof B3authAuthorizationToken) {
            SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(new B3authAuthorizationToken(1L, true));
            context.setAuthentication(authenticationResult);
            this.securityContextHolderStrategy.setContext(context);
            this.securityContextRepository.saveContext(context, request, response);

        }  else {
            throw new B3authAuthenticationException("Server authentication error.", "Wrong server configuration",
                    B3authAuthorizationServerExceptionCode.B5001);
        }

        filterChain.doFilter(request, response);
    }
}
