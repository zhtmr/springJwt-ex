package com.ex.springjwtex.service;

import com.ex.springjwtex.dto.CustomUserDetails;
import com.ex.springjwtex.entity.User;
import com.ex.springjwtex.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {
  private final UserRepository userRepository;

  public CustomUserDetailsService(UserRepository userRepository) {
    this.userRepository = userRepository;
  }

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    User user = userRepository.findByUsername(username);
    if (user != null) {
      //UserDetails에 담아서 return하면 AuthenticationManager 검증 함
      return new CustomUserDetails(user);
    }
    return null;
  }
}
