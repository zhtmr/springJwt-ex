package com.ex.springjwtex.service;

import com.ex.springjwtex.dto.JoinDto;
import com.ex.springjwtex.entity.User;
import com.ex.springjwtex.repository.UserRepository;
import org.springframework.beans.BeanUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class JoinService {
  private final UserRepository userRepository;
  private final BCryptPasswordEncoder passwordEncoder;

  public JoinService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
    this.userRepository = userRepository;
    this.passwordEncoder = passwordEncoder;
  }

  public void joinProcess(JoinDto joinDto) {
    String username = joinDto.getUsername();
    String password = joinDto.getPassword();

    Boolean isExist = userRepository.existsByUsername(username);
    if (isExist) {
      return;
    }

    User user = new User();
    user.setUsername(username);
    user.setPassword(passwordEncoder.encode(password));
    user.setRole("ROLE_ADMIN");
    userRepository.save(user);
  }

}
