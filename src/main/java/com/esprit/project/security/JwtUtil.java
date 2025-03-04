package com.esprit.project.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
public class JwtUtil {

    private static final Logger logger = LoggerFactory.getLogger(JwtUtil.class);

    private static final long EXPIRATION_TIME = 60 * 60 * 1000; // 1 hour in milliseconds

    private static final SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    // ✅ Generate JWT Token
    public String generateToken(String username, String role) {
        return Jwts.builder()
                .setSubject(username)
                .claim("role", role)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                .signWith(key, SignatureAlgorithm.HS512)
                .compact();
    }


    // ✅ Extract Username from JWT
    public String extractUsername(String token) {
        return parseClaims(token).getSubject();
    }

    // ✅ Extract Roles from JWT
    public String extractRole(String token) {
        return parseClaims(token).get("role", String.class);
    }


    // ✅ Validate JWT Token
    public boolean validateToken(String token, String username, String role) {
        try {
            final String extractedUsername = extractUsername(token);
            final String extractedRole = extractRole(token);
            return extractedUsername.equals(username) && extractedRole.equals(role) && !isTokenExpired(token);
        } catch (JwtException | IllegalArgumentException e) {
            logger.error("JWT validation error: {}", e.getMessage());
            return false; // Invalid token
        }
    }


    // ✅ Check Token Expiry
    private boolean isTokenExpired(String token) {
        return parseClaims(token).getExpiration().before(new Date());
    }

    // ✅ Parse Claims (Refactored to avoid redundant parsing)
    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}