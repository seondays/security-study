package com.example.securityStudy.config;

import com.example.securityStudy.service.CustomOAuth2UserService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
// 시큐리티가 활성화 될 수 있도록
@EnableWebSecurity
public class SecurityConfig {
    private final CustomOAuth2UserService customOAuth2UserService;

    public SecurityConfig(CustomOAuth2UserService customOAuth2UserService) {
        this.customOAuth2UserService = customOAuth2UserService;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 사용하지 않을 것들을 비활성화
        // 개발환경에라 csrf 비활성, 폼로그인이랑 베이직 방식도 안쓸거라 비활성
        http.csrf(csrf -> csrf.disable());
        http.formLogin(login -> login.disable());
        http.httpBasic(basic -> basic.disable());

        // Oauth2 세팅, 만일 aouth2Client를 사용하는 경우에는 필터를 커스텀해줘야 한다
//        http.oauth2Login(Customizer.withDefaults());

        // 디폴트 값을 지우고, 람다 형식으로 유저 엔드포인트 설정하기. -> UserDetailService를 등록해주는 엔드포인트다
        http.oauth2Login(oauth2 -> oauth2
                // 직접 커스텀 한 로그인 페이지가 있다면 해당 요청을 받을 컨트롤러를 등록
                .loginPage("/login")
                .userInfoEndpoint(userInfoEndpointConfig -> userInfoEndpointConfig.userService(customOAuth2UserService)));

        http.authorizeHttpRequests(auth -> auth.requestMatchers("/","/login","/oauth2**").permitAll()
                .anyRequest().authenticated());
        return http.build();
    }
}
