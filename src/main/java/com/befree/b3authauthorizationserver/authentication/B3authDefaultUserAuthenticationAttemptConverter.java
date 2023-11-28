package com.befree.b3authauthorizationserver.authentication;

import com.befree.b3authauthorizationserver.B3authAuthenticationAttemptToken;
import com.befree.b3authauthorizationserver.B3authAuthenticationException;
import com.befree.b3authauthorizationserver.B3authAuthorizationServerExceptionCode;
import com.nimbusds.jose.util.JSONObjectUtils;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StreamUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.util.Map;

public class B3authDefaultUserAuthenticationAttemptConverter implements AuthenticationConverter {
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

        if(!body.containsKey("email")) {
            throw new B3authAuthenticationException("Bad request",
                    "Email param is required in body.",
                    B3authAuthorizationServerExceptionCode.B4004);
        }

        if(body.get("email") instanceof String email) {
            return new B3authAuthenticationAttemptToken(email);
        }

        return null;
    }

}
