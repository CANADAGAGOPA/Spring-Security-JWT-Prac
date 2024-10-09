package com.example.TestSpringJWT.config.jwt;

import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    private SecretKey secretKey;


    public JWTUtil(@Value("${jwt.secret-key}") String secretKey) {

        this.secretKey = new SecretKeySpec(
                secretKey.getBytes(StandardCharsets.UTF_8),
                Jwts.SIG.HS256.key().build().getAlgorithm()
        );
    }

    public String getUsername(String token) {

        return Jwts
                .parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("username", String.class); // username 을 가져옴
    }

    public String getRole(String token) {

        return Jwts
                .parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .get("role", String.class); // role 을 가져옴
    }

    public Boolean isExpired(String token) {

        return Jwts
                .parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getExpiration()
                .before(new Date()); // 만료 여부를 확인
    }

    public String createJwt(String username, String role, Long expiredMs) {

        return Jwts.builder()
                .claim("username", username) // 토큰에 username 을 저장
                .claim("role", role) // 토큰에 role 을 저장
                .issuedAt(new Date(System.currentTimeMillis())) // 토큰 발급 시간
                .expiration(new Date(System.currentTimeMillis() + expiredMs)) // 토큰 만료 시간
                .signWith(secretKey) // 서명
                .compact(); // 생성
    }
}
