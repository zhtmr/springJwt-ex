package com.ex.springjwtex.controller;

import com.ex.springjwtex.dto.JoinDto;
import com.ex.springjwtex.service.JoinService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JoinController {
  private final JoinService joinService;

  public JoinController(JoinService joinService) {
    this.joinService = joinService;
  }

  @PostMapping("/join")
  public String joinProcess(JoinDto joinDto) {

    joinService.joinProcess(joinDto);
    return "ok";
  }
}
