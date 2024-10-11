package com.example.TestSpringJWT.config.jwt;

import com.example.TestSpringJWT.domain.UserEntity;
import com.example.TestSpringJWT.dto.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JWTFilter extends OncePerRequestFilter {

    private final JWTUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

        // request 에서 Authorization 헤더를 가져옴
        String authorization = request.getHeader("Authorization");

        // 헤더 검증
        if (authorization == null || !authorization.startsWith("Bearer")) {

            log.info("token null");

            filterChain.doFilter(request, response);

            // 조건이 해당되면 메서드 종료 (필수)
            return;
        }

        String token = authorization.split(" ")[1]; // Bearer 뒤에 있는 토큰만 추출

        // 토큰 소멸 시간 검증
        if (jwtUtil.isExpired(token)) {

            log.info("token expired");

            filterChain.doFilter(request, response);

            return;
        }

        String username = jwtUtil.getUsername(token); // 토큰에서 username 추출
        String role = jwtUtil.getRole(token); // 토큰에서 role 추출

        UserEntity userEntity = UserEntity.builder()
                .username(username)
                .password("tempPassword") // 비밀번호는 필요 없으므로 임시로 넣어줌
                .role(role)
                .build();

        // UserDetails 에 회원 정보 객체 저장
        CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

        // 스프링 시큐리티 인증 토큰 생성
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                customUserDetails,
                null,
                customUserDetails.getAuthorities()
        );

        // 세션에 사용자 등록
        SecurityContextHolder.getContext().setAuthentication(authToken);

        filterChain.doFilter(request, response);
    }
}

