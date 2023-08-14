package com.befree.b3authauthorizationserver.config.configurer;

import com.befree.b3authauthorizationserver.settings.B3authAuthorizationServerSettings;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.function.Supplier;

final class B3authAuthorizationServerContextFilter extends OncePerRequestFilter {
    private final B3authAuthorizationServerSettings authorizationServerSettings;

    B3authAuthorizationServerContextFilter(B3authAuthorizationServerSettings authorizationServerSettings) {
        Assert.notNull(authorizationServerSettings, "authorizationServerSettings cannot be null");
        this.authorizationServerSettings = authorizationServerSettings;
    }

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            AuthorizationServerContext authorizationServerContext = new DefaultAuthorizationServerContext(() -> {
                return resolveIssuer(this.authorizationServerSettings, request);
            }, this.authorizationServerSettings);
            AuthorizationServerContextHolder.setContext(authorizationServerContext);
            filterChain.doFilter(request, response);
        } finally {
            AuthorizationServerContextHolder.resetContext();
        }

    }

    private static String resolveIssuer(B3authAuthorizationServerSettings authorizationServerSettings, HttpServletRequest request) {
        return authorizationServerSettings.getIssuer() != null ? authorizationServerSettings.getIssuer() : getContextPath(request);
    }

    private static String getContextPath(HttpServletRequest request) {
        return UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request)).replacePath(request.getContextPath()).replaceQuery((String)null).fragment((String)null).build().toUriString();
    }

    private record DefaultAuthorizationServerContext(Supplier<String> issuerSupplier,
                                                     B3authAuthorizationServerSettings authorizationServerSettings) implements AuthorizationServerContext {

        public String getIssuer() {
                return this.issuerSupplier.get();
            }
    }
}
