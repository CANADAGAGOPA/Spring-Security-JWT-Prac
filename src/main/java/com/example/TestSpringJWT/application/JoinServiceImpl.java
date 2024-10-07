package com.example.TestSpringJWT.application;

import com.example.TestSpringJWT.domain.UserEntity;
import com.example.TestSpringJWT.dto.JoinDTO;
import com.example.TestSpringJWT.infrastructure.UserRepository;
import com.example.TestSpringJWT.type.RoleType;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor // 생성자 주입
@Transactional(readOnly = true) // 읽기 전용
public class JoinServiceImpl implements JoinService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    @Override
    @Transactional
    public void joinProcess(JoinDTO joinDTO) {

        // db 에 이미 존재하는 유저인지 확인
        boolean userExists = userRepository.findByUsername(joinDTO.getUsername()).isPresent();

        if (userExists) {
            throw new IllegalArgumentException("이미 존재하는 유저입니다.");
        }

        // 유저 정보 저장
        UserEntity userEntity = UserEntity.builder()
                .username(joinDTO.getUsername())
                .password(bCryptPasswordEncoder.encode(joinDTO.getPassword()))
                .role("ROLE_" + RoleType.ADMIN.name())
                .build();

        userRepository.save(userEntity);
    }
}
