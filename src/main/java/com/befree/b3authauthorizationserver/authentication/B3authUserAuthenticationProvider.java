package com.befree.b3authauthorizationserver.authentication;

import com.befree.b3authauthorizationserver.*;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;
import java.util.Objects;

public class B3authUserAuthenticationProvider implements AuthenticationProvider {
    private final B3authUserService b3authUserService;
    private final B3authAuthenticationAttemptService b3authAuthenticationAttemptService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public B3authUserAuthenticationProvider(B3authUserService b3authUserService,
                                            B3authAuthenticationAttemptService b3authAuthenticationAttemptService,
                                            BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.b3authUserService = b3authUserService;
        this.b3authAuthenticationAttemptService = b3authAuthenticationAttemptService;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        B3authAuthenticationToken b3authAuthenticationToken = (B3authAuthenticationToken) authentication;
        B3authUser user = b3authUserService.findByEmail(b3authAuthenticationToken.getEmail());

        if(user == null) {
            throw new B3authAuthenticationException("User cannot be found in database.",
                    "User does not exists.", B3authAuthorizationServerExceptionCode.B4005);
        }

        B3authAuthenticationAttempt authenticationAttempt
                = b3authAuthenticationAttemptService.findLastAttemptByUserId(user.getId());

        if(authenticationAttempt == null) {
            throw new B3authAuthenticationException("Authentication attempt does not exits in database.",
                    "User have to firstly attempt authentication and get code from email.",
                    B3authAuthorizationServerExceptionCode.B4006);
        }

        if(authenticationAttempt.getCreated().plusMinutes(5).isBefore(LocalDateTime.now())) {
            throw new B3authAuthenticationException("Authentication code expired.",
                    "Authentication code expired. Request a new one", B3authAuthorizationServerExceptionCode.B4007);
        }

        if(authenticationAttempt.isRevoked() || authenticationAttempt.isDeleted() || authenticationAttempt.isSucceed()) {
            throw new B3authAuthenticationException("B3authAuthenticationAttemptService should not return used authentication attempts.",
                    "Authentication attempt already used.", B3authAuthorizationServerExceptionCode.B4008);
        }

        if(!bCryptPasswordEncoder.matches(authenticationAttempt.getCode(), b3authAuthenticationToken.getCode())) {
            throw new B3authAuthenticationException("Code from email should be exactly the same as was sent.",
                    "Wrong email code.", B3authAuthorizationServerExceptionCode.B4009);
        }


        return new B3authAuthorizationToken(null, user.getId(), user.getInitialised(), user.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return B3authAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
