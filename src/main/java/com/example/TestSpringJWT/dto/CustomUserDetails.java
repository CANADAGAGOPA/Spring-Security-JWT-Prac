package com.example.TestSpringJWT.dto;

import com.example.TestSpringJWT.domain.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class CustomUserDetails implements UserDetails {

    private final UserEntity userEntity;

    public CustomUserDetails(UserEntity userData) {

        this.userEntity = userData;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() { // 권한을 가져오는 메소드

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {

                return userEntity.getRole();
            }
        });

        return collection;
    }

    @Override
    public String getPassword() { // 비밀번호를 가져오는 메소드

        return userEntity.getPassword();
    }

    @Override
    public String getUsername() { // 유저 이름을 가져오는 메소드

        return userEntity.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {

        return true;
    }

    @Override
    public boolean isAccountNonLocked() {

        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {

        return true;
    }

    @Override
    public boolean isEnabled() {

        return true;
    }
}
