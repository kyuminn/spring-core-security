package com.example.corespringsecurity.controller.user;

import com.example.corespringsecurity.domain.Account;
import com.example.corespringsecurity.domain.AccountDto;
import com.example.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

    // SecurityConfig.java에서  @Bean으로 선언한 passwordEncoder를 사용하는 예시
    // 기본 Encoding 알고리즘은 BCrypt
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @GetMapping(value="/mypage")
    public String myPage(){
        return "user/mypage";
    }

    @GetMapping("/users")
    public String createUser(){
        return "user/login/register";
    }

    @PostMapping("/users")
    public String createUser(AccountDto accountDto){
        Account account = new ModelMapper().map(accountDto, Account.class);
        account.setPassword(passwordEncoder.encode(account.getPassword()));
        userService.createUser(account);
        return "redirect:/";
    }
}
