package com.befree.b3authauthorizationserver.web;

import com.befree.b3authauthorizationserver.config.configuration.B3authEndpointsList;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.lang.NonNull;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.Writer;

public class NimbusJwkEndpointFilter extends OncePerRequestFilter {
    private final JWKSource<SecurityContext> jwkSource;
    private final JWKSelector jwkSelector;
    private final RequestMatcher requestMatcher;
    public NimbusJwkEndpointFilter(JWKSource<SecurityContext> jwkSource) {
        Assert.notNull(jwkSource, "jwkSource cannot be null");
        Assert.hasText(B3authEndpointsList.JWK, "jwk endpoint can't be null");
        this.jwkSource = jwkSource;
        this.jwkSelector = new JWKSelector((new JWKMatcher.Builder()).build());
        this.requestMatcher = new AntPathRequestMatcher(B3authEndpointsList.JWK, HttpMethod.GET.name());
    }
    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        if (!this.requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
        } else {
            JWKSet jwkSet;
            try {
                jwkSet = new JWKSet(this.jwkSource.get(this.jwkSelector, null));
            } catch (Exception exception) {
                throw new IllegalStateException("Failed to select the JWK(s) -> " + exception.getMessage(), exception);
            }

            response.setContentType("application/json");
            Writer writer = response.getWriter();

            try {
                writer.write(jwkSet.toString());
            } catch (Throwable exception) {
                if (writer != null) {
                    try {
                        writer.close();
                    } catch (Throwable var8) {
                        exception.addSuppressed(var8);
                    }
                }

                throw exception;
            }

            writer.close();
        }
    }
}
