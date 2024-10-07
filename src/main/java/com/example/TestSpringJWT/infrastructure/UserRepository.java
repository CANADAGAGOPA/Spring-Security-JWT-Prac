package com.example.TestSpringJWT.infrastructure;

import com.example.TestSpringJWT.domain.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<UserEntity, Long> {

    Optional<UserEntity> findByUsername(String username);
    // Optional: null 이 반환될 수 있는 메소드의 반환 타입으로 사용
}
