package com.example.oauth2.controller;


import com.example.oauth2.dto.SignupRequestDto;
import com.example.oauth2.security.UserDetailsImpl;
import com.example.oauth2.service.KakaoUserService;
import com.example.oauth2.service.UserService;
import com.fasterxml.jackson.core.JsonProcessingException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

@Slf4j
@Controller
public class UserController {

    private final UserService userService;
    private final KakaoUserService kakaoUserService;

    @Autowired
    public UserController(UserService userService, KakaoUserService kakaoUserService) {
        this.userService = userService;
        this.kakaoUserService = kakaoUserService;
    }

    @ResponseBody
    @GetMapping("/login-test")
    public String testRequest(@AuthenticationPrincipal UserDetailsImpl userDetails){

        return "user : " + userDetails.getUsername();
    }

    // 회원 로그인 페이지
    @GetMapping("/user/login")
    public String login() {
        return "login";
    }

    // 회원 가입 페이지
    @GetMapping("/user/signup")
    public String signup() {
        return "signup";
    }

    // 회원 가입 요청 처리
    @PostMapping("/user/signup")
    public String registerUser(SignupRequestDto requestDto) {
        userService.registerUser(requestDto);
        return "redirect:/user/login";
    }

// https://kauth.kakao.com/oauth/authorize?client_id=e0fa0a29b6f980a77e6cad8b0f96639d&redirect_uri=http://localhost:8080/user/kakao/callback&response_type=code
//        카카오로 로그인하기
    @GetMapping("/user/kakao/callback")
    public String kakaoLogin(@RequestParam String code) throws JsonProcessingException {
        log.info("param code : {}", code);
        kakaoUserService.kakaoLogin(code);
        return "redirect:/";
    }
}