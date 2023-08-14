package com.befree.b3authauthorizationserver.jwt;

import com.befree.b3authauthorizationserver.B3authAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

import java.net.URL;
import java.time.LocalDateTime;
import java.util.*;

public class JwtContext {
    private UUID subject;
    private URL issuer;
    private List<String> audience = new ArrayList<>();
    private LocalDateTime notBefore;
    private Collection<? extends GrantedAuthority> authorities;
    private Long secondsValid;
    private Map<String, Object> claims = new HashMap<>();
    public JwtContext() {
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder extends JwtContext {


        public Builder() {
        }

        public Builder subject(UUID subject) {
            super.subject = subject;
            return this;
        }

        public Builder issuer(URL issuer) {
            super.issuer = issuer;
            return this;
        }

        public Builder audience(List<String> audience) {
            Assert.notNull(audience, "audience must not be null");
            super.audience = audience;
            return this;
        }

        public Builder notBefore(LocalDateTime notBefore) {
            super.notBefore = notBefore;
            return this;
        }

        public Builder authorities(Collection<? extends GrantedAuthority> authorities) {
            super.authorities = authorities;
            return this;
        }

        public Builder secondsValid(Long secondsValid) {
            super.secondsValid = secondsValid;
            return this;
        }

        public Builder claims(Map<String, Object> claims) {
            super.claims = claims;
            return this;
        }

        public JwtContext build() {
            Assert.notNull(super.subject, "subject must not be null");
            Assert.notEmpty(super.authorities, "authorities must not be empty");

            var now = LocalDateTime.now();

            if(super.issuer == null) {
                try {
                    super.issuer = new URL("localhost");
                } catch(Exception e) {
                    throw new RuntimeException("can't proper build jwt url");
                }
            }

            if(super.notBefore == null) {
                super.notBefore = now;
            }

            if(super.secondsValid == null) {
                super.secondsValid = 300L;
            }

            return this;
        }
    }
}
