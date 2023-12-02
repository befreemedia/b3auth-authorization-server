package com.befree.b3authauthorizationserver.jwt;

import org.springframework.security.core.GrantedAuthority;

import java.net.URL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.UUID;

public interface JwtClaimsAccessor extends ClaimAccessor {


    default URL getIssuer() {
        return this.getClaim(B3authJwtClaims.ISSUER);
    }

    default List<String> getAudience() {
        return this.getClaim(B3authJwtClaims.AUDIENCE);
    }

    default LocalDateTime getExpiresAt() {
        var object = this.getClaim(B3authJwtClaims.EXPIRES_AT);
        if(object instanceof Date date) {
            return date.toInstant()
                    .atZone(ZoneId.systemDefault())
                    .toLocalDateTime();
        }
        return (LocalDateTime) object;
    }

    default LocalDateTime getNotBefore() {
        return this.getClaim(B3authJwtClaims.NOT_BEFORE);
    }

    default LocalDateTime getIssuedAt() {
        return this.getClaim(B3authJwtClaims.ISSUED_AT);
    }

    default UUID getId() {
        return this.getClaim(B3authJwtClaims.JWT_ID);
    }

    default UUID getSubject() {
        return this.getClaim(B3authJwtClaims.SUBJECT);
    }

    default Collection<? extends GrantedAuthority> getAuthorities() {
        return this.getClaim(B3authJwtClaims.AUTHORITIES);
    }
}
