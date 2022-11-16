package com.example.corespringsecurity.security.common;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
// 인증이 되지 않은 사용자가 인증이 필요한 자원에 접근하려고 할 때 예외 필터(ExceptionTranslationFilter)가 이 클래스의 commence() 호출
// 인증이 된 사용자가 해당 자원에 권한이 없을때는 예외 필터가(ExceptionTranslationFitler)가 AjaxAccessDeniedHandler의 handle() 호출
public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {
    // paramter로 인증 예외가 전달됨 (from ExceptionTranslationFilter)
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED,"UnAuthorized");
    }
}
