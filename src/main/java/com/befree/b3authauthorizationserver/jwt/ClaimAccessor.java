package com.befree.b3authauthorizationserver.jwt;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.util.Assert;

import java.net.URL;
import java.time.Instant;
import java.util.List;
import java.util.Map;

public interface ClaimAccessor {
    Map<String, Object> getClaims();

    default <T> T getClaim(String claim) {
        return !this.hasClaim(claim) ? null : (T) this.getClaims().get(claim);
    }

    default boolean hasClaim(String claim) {
        Assert.notNull(claim, "claim cannot be null");
        return this.getClaims().containsKey(claim);
    }
}
