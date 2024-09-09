package com.example.securityStudy.service;

import com.example.securityStudy.dto.CustomOAuth2User;
import com.example.securityStudy.dto.KaKaoResponse;
import com.example.securityStudy.dto.NaverResponse;
import com.example.securityStudy.dto.OAuth2Response;
import com.example.securityStudy.entity.UserEntity;
import com.example.securityStudy.repository.UserRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
//DefaultOAuth2UserService는 OAuth2UserService의 구현체. 둘 중 아무거나 상속받아도 상관없다
// 리소스 서버로부터 유저 정보를 받기 위해 만들어졌다. 기존 시큐리티 프로젝트의 UserDetailService의 역할
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    public CustomOAuth2UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    // 서버에서 전달받는 사용자 정보 데이터를 인자로 받는다. userRequest 는 여러 종류의 OAuth가 있을 경우 모든 종류가 다 넘어온다
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        // 부모 클래스를 통해서 유저 정보를 가지고 온다
        OAuth2User oAuth2User = super.loadUser(userRequest);
        System.out.println(oAuth2User.getAttributes());

        // 어떤 인증 프로바이더인지 가져오기
        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        // 프로바이더마다 각자 내용 규격이 다르기 때문에 각각 다른 방법으로 객체를 만들어야 한다.
        OAuth2Response oAuth2Response = null;
        if (registrationId.equals("naver")) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else if (registrationId.equals("kakao")) {
            oAuth2Response = new KaKaoResponse(oAuth2User.getAttributes());
            System.out.println("kakao");
        } else {
            return null;
        }
        // 이렇게 해서 넘겨주면, manager나 authentication provider가 로그인을 알아서 진행해준다
        // OAuthDetail를 만들어서 응답하자
        String role = "ROLE_USER";

        // 받아온 정보를 우리 DB에 저장하는 작업을 진행할 수 있다.
        String username = oAuth2Response.getProvider() + " " + oAuth2Response.getProviderId();

        // 유저가 DB에 있는지 확인
        UserEntity existData = userRepository.findByUsername(username);
        // 없는 경우 새로 저장
        if (existData == null) {
            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setRole(role);

            userRepository.save(userEntity);
        } else {
            // 있을 경우 조회 후에 업데이트 쳐주기
            role = existData.getRole();
            existData.setEmail(oAuth2Response.getEmail());
            userRepository.save(existData);
        }

        return new CustomOAuth2User(oAuth2Response, role);
    }
}
