package com.example.corespringsecurity.controller.login;

import com.example.corespringsecurity.domain.Account;
import org.springframework.boot.Banner;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

    // custom login page 매핑
    @GetMapping("/login")
    public String login(@RequestParam(value="error", required = false)String error,
                        @RequestParam(value="exception",required = false)String exception,
                        Model model){
        model.addAttribute("error",error);
        model.addAttribute("exception",exception);
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

    @GetMapping("/denied")
    public String accessDenied(@RequestParam(value="exception", required = false)String exception, Model model){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        //인증객체 안의 principal = User정보 .
        // 현재 이 프로젝트에서 User 정보에 해당하는 class 는 Account이므로 다운캐스팅
        Account account = (Account)authentication.getPrincipal();
        model.addAttribute("username",account.getUsername());
        model.addAttribute("exception",exception);

        return "user/login/denied";
    }
}
