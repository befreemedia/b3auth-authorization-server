package com.befree.b3authauthorizationserver.authentication;

import com.befree.b3authauthorizationserver.B3authAuthenticationException;
import com.befree.b3authauthorizationserver.B3authAuthorizationServerExceptionCode;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;

public class B3authDefaultUserAuthenticationConverter implements AuthenticationConverter {
    @Override
    public Authentication convert(HttpServletRequest request) {
        String email = request.getParameter("email");
        String code = request.getParameter("code");

        if(email == null) {
            throw new B3authAuthenticationException("Bad request", "Email param is required in body.", B3authAuthorizationServerExceptionCode.B4004)
        }

        if(code == null) {
            throw new B3authAuthenticationException("Bad request",
                    "Code param is required in body. To get code to email send request to /b3auth/attempt/",
                    B3authAuthorizationServerExceptionCode.B4004);
        }

        return new UsernamePasswordAuthenticationToken(email, code);
    }
}
