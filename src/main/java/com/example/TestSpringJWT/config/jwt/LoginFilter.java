package com.example.TestSpringJWT.config.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Slf4j
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // 로그인 시도시에 실행되는 메소드
    @Override
    public Authentication attemptAuthentication(
            HttpServletRequest request,
            HttpServletResponse response)
            throws AuthenticationException {

        // 클라이언트 요청에서 username, password 추출
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        log.info("username: " + username);

        // 스프링 시큐리티에서 username 과 password 를 검증하기 위해서는 token 에 담아야 함
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(username, password, null);

        // token 에 담은 검증을 위한 AuthenticationManager 로 전달
        return authenticationManager.authenticate(authToken);
    }

    // 로그인 성공시 실행하는 메소드 (여기서 JWT 를 발급하면 됨)
    @Override
    protected void successfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain,
            Authentication authentication) {

        log.info("로그인 성공");
    }

    // 로그인 실패시 실행하는 메소드
    @Override
    protected void unsuccessfulAuthentication(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException failed) {

        log.info("로그인 실패");
    }
}
