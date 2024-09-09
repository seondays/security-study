package com.example.securityStudy.dto;

public interface OAuth2Response {
    // 제공자 이름
    String getProvider();
    // 제공자 번호
    String getProviderId();
    // 사용자 이름
    String getEmail();
    // 사용자 이메일
    String getName();
}
