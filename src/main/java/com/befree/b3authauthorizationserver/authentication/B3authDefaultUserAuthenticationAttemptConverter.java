package com.befree.b3authauthorizationserver.authentication;

import com.befree.b3authauthorizationserver.B3authAuthenticationAttemptToken;
import com.befree.b3authauthorizationserver.B3authAuthenticationException;
import com.befree.b3authauthorizationserver.B3authAuthorizationServerExceptionCode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class B3authDefaultUserAuthenticationAttemptConverter implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {

        String email = request.getParameter("email");
        String code = request.getParameter("code");

        if(code != null) {
            return null;
        }

        if(email == null) {
            throw new B3authAuthenticationException("Bad request",
                    "Email param is required in body.",
                    B3authAuthorizationServerExceptionCode.B4004);
        }

        return new B3authAuthenticationAttemptToken(email);
    }

}
