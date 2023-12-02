package com.befree.b3authauthorizationserver.authentication;

import com.befree.b3authauthorizationserver.*;
import com.befree.b3authauthorizationserver.jwt.B3authJwtClaims;
import com.befree.b3authauthorizationserver.jwt.B3authTokenType;
import com.befree.b3authauthorizationserver.jwt.Jwt;
import com.befree.b3authauthorizationserver.jwt.JwtGenerator;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.Objects;

public class B3authUserTokenAuthenticationProvider implements AuthenticationProvider {
    private JwtGenerator jwtGenerator;
    private B3authSessionService b3authSessionService;
    private B3authUserService b3authUserService;

    public B3authUserTokenAuthenticationProvider(JwtGenerator jwtGenerator, B3authSessionService b3authSessionService,
                                                 B3authUserService b3authUserService) {
        this.jwtGenerator = jwtGenerator;
        this.b3authSessionService = b3authSessionService;
        this.b3authUserService = b3authUserService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        B3authBearerAuthenticationToken b3authBearerAuthenticationToken = (B3authBearerAuthenticationToken) authentication;

        String tokenHeaderValue = b3authBearerAuthenticationToken.getToken();

        Jwt token = jwtGenerator.parseAndVerify(tokenHeaderValue);


        if(token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new B3authAuthenticationException("Session expired.",
                    "Session is after expiration date.", B3authAuthorizationServerExceptionCode.B4009);
        }

        if(token.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new B3authAuthenticationException("Session expired.",
                    "Session is after expiration date.", B3authAuthorizationServerExceptionCode.B4009);
        }

        if(((Date) token.getClaim(B3authJwtClaims.NOT_BEFORE)).toInstant()
                .atZone(ZoneId.systemDefault())
                .toLocalDateTime().isAfter(LocalDateTime.now())) {
            throw new B3authAuthenticationException("Session is not available yet..",
                    "Token might be used after not before date..", B3authAuthorizationServerExceptionCode.B4009);
        }

        if(!Objects.equals(token.getType(), B3authTokenType.AUTHORIZATION_TOKEN)) {
            throw new B3authAuthenticationException("This token can't be used to authorization.",
                    "Only authorization token can be used to authorization.", B3authAuthorizationServerExceptionCode.B4009);
        }


        B3authSession session = b3authSessionService.findById(token.getId());

        if(session == null) {
            throw new B3authAuthenticationException("Session can't be found.",
                    "Session does not exist in database.", B3authAuthorizationServerExceptionCode.B4009);
        }

        if(session.getRevoked()) {
            throw new B3authAuthenticationException("Session revoked.",
                    "Session was revoked.", B3authAuthorizationServerExceptionCode.B4009);
        }

        if(session.getDeleted()) {
            throw new B3authAuthenticationException("Session deleted.",
                    "Session was deleted.", B3authAuthorizationServerExceptionCode.B4009);
        }

        if(session.getSuspended()) {
            throw new B3authAuthenticationException("Session suspended.",
                    "Session was suspended.", B3authAuthorizationServerExceptionCode.B4009);
        }

        if(session.getExpiresAt().isBefore(LocalDateTime.now())) {
            throw new B3authAuthenticationException("Session expired.",
                    "Session is after expiration date.", B3authAuthorizationServerExceptionCode.B4009);
        }

        if(!Objects.equals(session.getType(), "user-session")) {
            throw new B3authAuthenticationException("This token can't be used to authorization.",
                    "Only authorization token can be used to authorization.", B3authAuthorizationServerExceptionCode.B4009);
        }

        B3authUser user = b3authUserService.findById(session.getSubjectId());

        if(user == null) {
            throw new B3authAuthenticationException("User do not exist",
                    "User can't be found in database.", B3authAuthorizationServerExceptionCode.B4009);
        }

        // todo check user

        return new B3authAuthorizationToken(session.getId(), user.getId(), user.getInitialised(), user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return B3authBearerAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
