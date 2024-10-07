package com.example.TestSpringJWT.application;

import com.example.TestSpringJWT.domain.UserEntity;
import com.example.TestSpringJWT.dto.CustomUserDetails;
import com.example.TestSpringJWT.infrastructure.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Slf4j
@Service
@RequiredArgsConstructor // 생성자 주입
@Transactional(readOnly = true) // 읽기 전용
public class CustomUserDetailsServiceImpl implements CustomUserDetailsService, UserDetailsService {

    private final UserRepository userRepository;

    /**
     * 유저 정보를 가져오는 메소드
     * @param username
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Optional<UserEntity> userData = Optional.ofNullable(userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("해당 유저를 찾을 수 없습니다.")));

        UserEntity userEntity = userData.get(); // Optional 객체를 가져와 UserEntity 객체로 변환

        return new CustomUserDetails(userEntity);
    }
}
