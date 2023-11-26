package com.befree.b3authauthorizationserver.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.factories.DefaultJWSSignerFactory;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jose.produce.JWSSignerFactory;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.net.URL;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

public class JwtGenerator {
    private final static String ALGORITHM = "RSA256";
    private final JWKSource<SecurityContext> jwkSource;
    private final JWSSignerFactory jwsSignerFactory = new DefaultJWSSignerFactory();

    public JwtGenerator(JWKSource<SecurityContext> jwkSource) {
        this.jwkSource = jwkSource;
    }

    public Jwt generate(UUID uuid, String type, Long secondsValid, LocalDateTime notBefore, Map<String, Object> claims,
                        Long subjectId, List<String> audience, Collection<? extends GrantedAuthority> authorities,
                               URL issuer) {

        LocalDateTime issuedAt = LocalDateTime.now();
        LocalDateTime expiresAt = notBefore.plusSeconds(secondsValid);

        claims.put(B3authJwtClaims.SUBJECT, subjectId);
        claims.put(B3authJwtClaims.TOKEN_TYPE, type);
        claims.put(B3authJwtClaims.JWT_ID, uuid);
        claims.put(B3authJwtClaims.AUDIENCE, audience);
        claims.put(B3authJwtClaims.AUTHORITIES, authorities);
        claims.put(B3authJwtClaims.EXPIRES_AT, expiresAt);
        claims.put(B3authJwtClaims.ISSUED_AT, issuedAt);
        claims.put(B3authJwtClaims.ISSUER, issuer);
        claims.put(B3authJwtClaims.NOT_BEFORE, notBefore);

        JWKMatcher jwkMatcher = new JWKMatcher.Builder().algorithm(Algorithm.parse(ALGORITHM)).build();

        JWKSelector jwkSelector = new JWKSelector(jwkMatcher);

        try {
            List<JWK> jwks = jwkSource.get(jwkSelector, null);

            JWK jwk = jwks.get(0);

            String value = serialize(claims, jwk);
            if(Objects.equals(type, B3authTokenType.REFRESH_TOKEN)) {
                return new RefreshToken(uuid, value, expiresAt, issuedAt, claims);
            } else {
                return new AuthorizationToken(uuid, value, expiresAt, issuedAt, claims);
            }
        } catch (Exception e) {
            System.out.println("i will do some handling, i promise");
        }
        return null;
    }

    private String serialize(Map<String, Object> claims, JWK jwk) throws JOSEException {
        JWSHeader jwsHeader = generateHeaders(ALGORITHM);
        JWTClaimsSet jwtClaimsSet = convertClaims(claims);
        JWSSigner jwsSigner = jwsSignerFactory.createJWSSigner(jwk);
        SignedJWT signedJwt = new SignedJWT(jwsHeader, jwtClaimsSet);

        try {
            signedJwt.sign(jwsSigner);
        } catch (Exception e) {
            System.out.println("as i said above, i will do it...");
        }

        return signedJwt.serialize();
    }

    private static JWSHeader generateHeaders(String algorithm) {
        JWSHeader.Builder builder = new JWSHeader.Builder(JWSAlgorithm.parse(algorithm));
        builder.type(JOSEObjectType.JWT);

        return builder.build();
    }

    private static JWTClaimsSet convertClaims(Map<String, Object> claims) {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

        Object issuer = claims.get(B3authJwtClaims.ISSUER);
        if (issuer != null) {
            builder.issuer(issuer.toString());
        }

        String subject = (String) claims.get(B3authJwtClaims.SUBJECT);
        if (StringUtils.hasText(subject)) {
            builder.subject(subject);
        }

        List<String> audience = (List<String>) claims.get(B3authJwtClaims.AUDIENCE);
        if (audience != null && !CollectionUtils.isEmpty(audience)) {
            builder.audience(audience);
        }

        LocalDateTime expiresAt = (LocalDateTime) claims.get(B3authJwtClaims.EXPIRES_AT);
        if (expiresAt != null) {
            builder.expirationTime(Date.from(expiresAt.atZone(ZoneId.systemDefault()).toInstant()));
        }

        LocalDateTime notBefore = (LocalDateTime) claims.get(B3authJwtClaims.NOT_BEFORE);
        if (notBefore != null) {
            builder.notBeforeTime(Date.from(notBefore.atZone(ZoneId.systemDefault()).toInstant()));
        }

        LocalDateTime issuedAt = (LocalDateTime) claims.get(B3authJwtClaims.ISSUED_AT);
        if (issuedAt != null) {
            builder.issueTime(Date.from(issuedAt.atZone(ZoneId.systemDefault()).toInstant()));
        }

        UUID jwtId = (UUID) claims.get(B3authJwtClaims.JWT_ID);
        if (jwtId != null) {
            builder.jwtID(jwtId.toString());
        }

        Map<String, Object> customClaims = new HashMap<>();
        claims.forEach((name, value) -> {
            if (!JWTClaimsSet.getRegisteredNames().contains(name)) {
                customClaims.put(name, value);
            }

        });

        if (!customClaims.isEmpty()) {
            Objects.requireNonNull(builder);
            customClaims.forEach(builder::claim);
        }

        return builder.build();
    }
}
