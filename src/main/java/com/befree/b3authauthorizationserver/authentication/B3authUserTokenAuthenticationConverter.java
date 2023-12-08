package com.befree.b3authauthorizationserver.authentication;

import com.befree.b3authauthorizationserver.*;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;


public class B3authUserTokenAuthenticationConverter implements AuthenticationConverter {
    @Override
    @Nullable
    public Authentication convert(HttpServletRequest request) {

        String authorizationHeader = request.getHeader("Authorization");

        if(authorizationHeader == null) {
            throw new B3authAuthenticationException("Bad request",
                    "Authorization header is required.",
                    B3authAuthorizationServerExceptionCode.B4004);
        }

        if(!StringUtils.startsWithIgnoreCase(authorizationHeader, "bearer ")) {
            throw new B3authAuthenticationException("Bad request",
                    "Authorization header have to start with Bearer phrase",
                    B3authAuthorizationServerExceptionCode.B4004);
        }

        var token = authorizationHeader.substring(7);



        return new B3authBearerAuthenticationToken(token);
    }
}
