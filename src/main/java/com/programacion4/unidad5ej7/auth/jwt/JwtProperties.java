package com.programacion4.unidad5ej7.auth.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.jwt")
public record JwtProperties(
        String secret,
        long accessExpirationMs,
        long refreshExpirationMs,
        String algorithm
) {
    public long expirationMs() {
        return 0;
    }
}