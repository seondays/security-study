package com.example.testjwtsecurity.service;

import com.example.testjwtsecurity.dto.JoinDto;
import com.example.testjwtsecurity.entity.UserEntity;
import com.example.testjwtsecurity.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {
    private final UserRepository userRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public JoinService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    public void joinProcess(JoinDto joinDto) {
        String username = joinDto.getUsername();
        String password = joinDto.getPassword();

        if (userRepository.existsByUsername(username)) {
            return;
        }

        UserEntity data = new UserEntity();
        data.setUsername(username);
        // 패스워드 세팅 시에 무조건 암호화
        data.setPassword(bCryptPasswordEncoder.encode(password));
        data.setRole("ROLE_ADMIN");

        userRepository.save(data);
    }
}
