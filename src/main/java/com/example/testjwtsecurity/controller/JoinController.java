package com.example.testjwtsecurity.controller;

import com.example.testjwtsecurity.dto.JoinDto;
import com.example.testjwtsecurity.service.JoinService;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody
public class JoinController {
    private final JoinService joinService;

    public JoinController(JoinService joinService) {
        this.joinService = joinService;
    }

    @PostMapping("/join")
    public String joinP(JoinDto joinDto) {
        joinService.joinProcess(joinDto);
        return "ok";
    }
}
