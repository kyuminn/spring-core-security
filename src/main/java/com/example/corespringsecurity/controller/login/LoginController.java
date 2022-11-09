package com.example.corespringsecurity.controller.login;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

    // custom login page 매핑
    @GetMapping("/login")
    public String login(){
        return "user/login/login";
    }
    //LogoutHandelr를 이용해서 get 방식의 logout 구현
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // 인증객체가 null이 아닌 경우 로그아웃 처리
        if(authentication!= null){
            new SecurityContextLogoutHandler().logout(request,response,authentication);
        }
        return "redirect:/login";
    }
}
