package com.example.testjwtsecurity.jwt;

import com.example.testjwtsecurity.dto.CustomUserDetails;
import com.example.testjwtsecurity.entity.UserEntity;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

// 토큰을 받았을 때 이 토큰을 검증하는 역할을 담당하는 클래스
// OncePerRequestFilter 를 상속받았기 때문에 모든 경로에 대해 request 시 동작한다
public class JwtFilter extends OncePerRequestFilter {

    // 필터링을 위해 JWTUtil을 주입받아 내부의 검증 메서드를 사용할 것
    private final JwtUtil jwtUtil;

    public JwtFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        // request에서 Authorization 헤더를 찾고 검증한다.
        String authorization = request.getHeader("Authorization");
        // 만약 토큰이 없거나 잘못된 경우
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("Token null");

            // 현재 필터를 종료하고 다음 필터 체인으로 값을 넘겨준다.
            filterChain.doFilter(request, response);
            // 유효한 토큰이 아니니 메서드 종료
            return;
        }

        // 다음으로 검증할 것이 토큰 자체 내용들이다
        String token = authorization.split(" ")[1]; // 토큰에서 Bearer 제거

        // 먼저 만료 확인
        if (jwtUtil.isExpired(token)) {
            System.out.println("token Expired");
            filterChain.doFilter(request, response);
            // 유효한 토큰이 아니니 메서드 종료
            return;
        }

        // 토큰의 내용 확인 시작 : 일시적인 세션을 만들어서 유저 정보를 일시적으로 저장하자
        String username = jwtUtil.getUserName(token);
        String role = jwtUtil.getRole(token);

        // 정보를 가지고 유저 생성
        UserEntity user = new UserEntity();
        user.setUsername(username);
        user.setRole(role);
        user.setPassword("password");

        // userDetails에 유저 정보 담기
        CustomUserDetails customUserDetails = new CustomUserDetails(user);

        // 스프링 시큐리티 인증 토큰 생성
        Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());

        // 세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}
