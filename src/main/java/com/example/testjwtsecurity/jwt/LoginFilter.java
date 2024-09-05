package com.example.testjwtsecurity.jwt;

import com.example.testjwtsecurity.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 로그인 필터는 UsernamePasswordAuthenticationFilter 필터를 상속받았기 때문에 로그인 요청에서만 동작한다.
public class LoginFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public LoginFilter(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @Override
    // 요청을 가로채서 인증을 진행하기 위한 부분 작성
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 요청에서 온 유저네임/패스워드 정보를 가져온다
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        //  AuthenticationManager에 전달해주기 위해 유저의 정보를 토큰에 담는다
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username,password,null);

        // 토큰 전달해주면 해당 객체가 검증을 진행한다. 검증이 완료된 후에 Authentication 객체를 만들어서 최종적으로 return된다
        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공 시 실행되는 메서드
    // jwt를 만들어서 헤더에 넣어 준다.
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain, Authentication authentication)
            throws IOException, ServletException {
        CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

        // 이름을 가져온다
        String username = customUserDetails.getUsername();

        // 롤을 가져온다
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends  GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority authority = iterator.next();

        String role = authority.getAuthority();

        // 뽑아낸 정보를 가지고 토큰을 만들어달라고 jwtutil에 요청하기
        String token = jwtUtil.creatJwt(username, role, 60*60*10L);

        // 만들어진 토큰을 헤더에 담는다.
        response.addHeader("Authorization","Bearer " + token);
    }

    // 로그인 실패 시 실행되는 메서드
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request,
            HttpServletResponse response, AuthenticationException failed)
            throws IOException, ServletException {
        response.setStatus(401);
    }
}
