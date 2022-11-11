package com.example.corespringsecurity.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    // 인증 전에 사용자가 가고자 했던 URL을 담고 있는 객체 참조
    // 인증 후에 이 객체 안에 있는 URL을 이용하여 바로 원래 가려고 했던 페이지로 redirect 할 수 있음.
    private RequestCache requestCache = new HttpSessionRequestCache();
    private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();


    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        setDefaultTargetUrl("/");
        SavedRequest savedRequest = requestCache.getRequest(request,response);
        // 이전에 요청한 페이지가 없는 경우 (바로 로그인 을 클릭한 경우)에는 request 객체가 null일 수 있기 때문에 null check 필수!
        if(savedRequest!=null){
            String targetUrl = savedRequest.getRedirectUrl();
            redirectStrategy.sendRedirect(request,response,targetUrl);
        }else{ //  이전 요청 객체가 null인 경우 모두 / 로 이동처리
            redirectStrategy.sendRedirect(request,response,getDefaultTargetUrl());
        }

    }
}
