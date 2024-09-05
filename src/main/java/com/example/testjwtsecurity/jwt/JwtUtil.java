package com.example.testjwtsecurity.jwt;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Jwts.SIG;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {
    private SecretKey secretKey;

    public JwtUtil(@Value("${spring.jwt.secret}")String secret) {
        // 우리가 application properties에 저장해둔 키(그냥 텍스트)를 JWT에서 사용하는 객체로 만들어서 사용해야 한다.
        this.secretKey = new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), SIG.HS256.key().build().getAlgorithm());
    }

    // 검증을 진행할 메서드들을 선언한다.
    public String getUserName(String token) {
        // String 값인 토큰을 전달받아서 내부적으로 JWT parser를 이용해서 맞는지 확인하는 작업이다.
        // 토큰은 암호화가 되어있는 상태라 secretKey를 사용해서 검증
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("username",String.class);
    }

    public String getRole(String token) {
        // 마찬가지로 토큰에서 role 값을 가져오는 것
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().get("role", String.class);
    }

    public Boolean isExpired(String token) {
        // 해당 토큰을 확인해서 토큰이 만료되었는지를 확인한다
        return Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(token).getPayload().getExpiration().before(new Date());
    }

    // 토큰을 생성하는 메서드
    public String creatJwt(String username, String role, Long expiredMs) {
        return Jwts.builder()
                // claim 메서드를 통해 특정한 키에 대한 값을 넣어줄 수 있다.
                .claim("username", username)
                .claim("role", role)
                // 토큰이 언제 발행되었는지 발행시간 넣어 주기
                .issuedAt(new Date(System.currentTimeMillis()))
                .expiration(new Date(System.currentTimeMillis() + expiredMs))
                // secretKey를 통해서 토큰 시그니처를 만들어서 암호화를 진행해야 한다.
                .signWith(secretKey)
                .compact();
    }
}
