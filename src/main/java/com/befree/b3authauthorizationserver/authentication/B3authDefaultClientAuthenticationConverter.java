package com.befree.b3authauthorizationserver.authentication;

import com.befree.b3authauthorizationserver.B3authAuthenticationException;
import com.befree.b3authauthorizationserver.B3authAuthenticationToken;
import com.befree.b3authauthorizationserver.B3authAuthorizationServerExceptionCode;
import com.befree.b3authauthorizationserver.B3authClientAuthenticationToken;
import com.nimbusds.jose.util.JSONObjectUtils;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StreamUtils;

import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Map;

public class B3authDefaultClientAuthenticationConverter implements AuthenticationConverter {
    @Override
    @Nullable
    public Authentication convert(HttpServletRequest request) {

        Map<String, Object> body;

        try {
            InputStream requestInputStream = request.getInputStream();
            String stringBody = StreamUtils.copyToString(requestInputStream, Charset.defaultCharset());
            body = JSONObjectUtils.parse(stringBody);
        } catch (Exception e) {
            return null;
        }

        if(!body.containsKey("login")) {
            throw new B3authAuthenticationException("Bad request",
                    "Email param is required in body.",
                    B3authAuthorizationServerExceptionCode.B4004);
        }

        if(!body.containsKey("password")) {
            throw new B3authAuthenticationException("Bad request",
                    "Code param is required in body. To get code to email send request to /b3auth/attempt/",
                    B3authAuthorizationServerExceptionCode.B4004);
        }

        String login;
        String password;

        if(body.get("login") instanceof String loginData) {
            login = loginData;
        } else {
            throw new B3authAuthenticationException("Bad request",
                    "Login must be string.",
                    B3authAuthorizationServerExceptionCode.B4004);
        }

        if(body.get("password") instanceof String passwordData) {
            password = passwordData;
        } else {
            throw new B3authAuthenticationException("Bad request",
                    "Password must be string.",
                    B3authAuthorizationServerExceptionCode.B4004);
        }


        return new B3authClientAuthenticationToken(login, password);
    }
}
