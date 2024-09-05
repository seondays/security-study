package com.example.testjwtsecurity.config;

import com.example.testjwtsecurity.jwt.JwtFilter;
import com.example.testjwtsecurity.jwt.JwtUtil;
import com.example.testjwtsecurity.jwt.LoginFilter;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Collections;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
// security를 위한 configuration이라는 의미
@EnableWebSecurity
public class SecurityConfig {
    //AuthenticationManager가 인자로 받을 AuthenticationConfiguraion 객체 생성자 주입
    private final AuthenticationConfiguration authenticationConfiguration;
    private final JwtUtil jwtUtil;

    public SecurityConfig(AuthenticationConfiguration authenticationConfiguration, JwtUtil jwtUtil) {
        this.authenticationConfiguration = authenticationConfiguration;
        this.jwtUtil = jwtUtil;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //cors 에러 해결
        http.cors(cors -> cors.configurationSource(new CorsConfigurationSource() {
            @Override
            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                CorsConfiguration configuration = new CorsConfiguration();

                // 허용할 프론트엔트 주소
                configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
                // 모든 메서드 허용
                configuration.setAllowedMethods(Collections.singletonList("*"));
                // 프론트쪽에서 credentials 처리를 하면 여기에 true로 설정해줘야 함
                configuration.setAllowCredentials(true);
                // 허용할 헤더
                configuration.setAllowedHeaders(Collections.singletonList("*"));
                // 허용할 시간
                configuration.setMaxAge(3600L);
                // JWT를 보낼 것이기 때문에 authorization 헤더를 여기 설정
                configuration.setExposedHeaders(Collections.singletonList("Authorization"));
                return configuration;
            }
        }));
        // csrf disable 토큰으로 진행할 때는 세션보다 csrf 공격에 대해 크게 걱정하지 않아도 됨
        http.csrf(auth -> auth.disable());

        //From 로그인 방식 disable
        // 이렇게 disable 하면 해당하는 필터만 꺼지는 것인가?
        http.formLogin(auth -> auth.disable());

        //http basic 인증 방식 disable
        http.httpBasic(auth -> auth.disable());

        // 경로별 인가 작업
        http.authorizeHttpRequests(auth ->
                auth.requestMatchers("/login","/","/join").permitAll()
                        .requestMatchers("admin").hasRole("ADMIN")
                        .anyRequest().authenticated());

        // 토큰 방식에서는 세션을 stateless로 관리하고 있으므로 세션 설정을 stateless로 변경
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));


        // 우리가 만든 필터를 사용할 수 있게 등록해줘야 함. 기존에 있던 필터를 대체해서 사용하는 것이기 때문에 해당 자리에 넣어줄 것이다.
        http.addFilterAt(new LoginFilter(authenticationManager(authenticationConfiguration), jwtUtil), UsernamePasswordAuthenticationFilter.class);

        http.addFilterAfter(new JwtFilter(jwtUtil), LoginFilter.class);

        return http.build();
    }

    //loginfilter를 위한AuthenticationManager Bean 등록
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
