package com.befree.b3authauthorizationserver.authentication;

import com.befree.b3authauthorizationserver.B3authAuthenticationException;
import com.befree.b3authauthorizationserver.B3authAuthenticationToken;
import com.befree.b3authauthorizationserver.B3authAuthorizationServerExceptionCode;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class B3authDefaultClientAuthenticationConverter implements AuthenticationConverter {
    @Override
    @Nullable
    public Authentication convert(HttpServletRequest request) {

        String login = request.getParameter("login");
        String password = request.getParameter("password");

        if(login == null) {
            throw new B3authAuthenticationException("Bad request",
                    "Email param is required in body.",
                    B3authAuthorizationServerExceptionCode.B4004);
        }

        if(password == null) {
            throw new B3authAuthenticationException("Bad request",
                    "Password param is required in body. To get code to login send request to /b3auth/attempt/",
                    B3authAuthorizationServerExceptionCode.B4004);
        }

        return new B3authAuthenticationToken(login, password);
    }
}
