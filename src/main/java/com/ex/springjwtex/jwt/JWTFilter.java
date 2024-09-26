package com.ex.springjwtex.jwt;

import com.ex.springjwtex.dto.CustomUserDetails;
import com.ex.springjwtex.entity.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class JWTFilter extends OncePerRequestFilter {

  private final JWTUtil jwtUtil;

  public JWTFilter(JWTUtil jwtUtil) {
    this.jwtUtil = jwtUtil;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    String authorization = request.getHeader("Authorization");

    // 헤더검증
    if (authorization == null || !authorization.startsWith("Bearer ")) {
      System.out.println("token null");
      filterChain.doFilter(request, response);
      return;
    }

    // "Bearer " 제거
    String token = authorization.split(" ")[1];

    // 토큰 소멸 확인
    if (jwtUtil.isExpired(token)) {
      System.out.println("token expired");
      filterChain.doFilter(request, response);
      return;
    }

    String username = jwtUtil.getUsername(token);
    String role = jwtUtil.getRole(token);

    User userEntity = new User();
    userEntity.setUsername(username);
    userEntity.setPassword("temppassword");   // jwt 에는 비번 정보가 없다. 매번 db 조회하지 않기 위해 임시 비번으로 세팅한다.
    userEntity.setRole(role);

    CustomUserDetails customUserDetails = new CustomUserDetails(userEntity);

    //스프링 시큐리티 인증 토큰 생성
    Authentication authToken = new UsernamePasswordAuthenticationToken(customUserDetails, null, customUserDetails.getAuthorities());
    //세션에 사용자 등록
    SecurityContextHolder.getContext().setAuthentication(authToken);

    filterChain.doFilter(request, response);

  }
}
