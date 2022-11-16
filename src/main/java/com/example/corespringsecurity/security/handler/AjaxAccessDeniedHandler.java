package com.example.corespringsecurity.security.handler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
// 인증을 받은 사용자이지만 해당 자원에 인가받지 않았으면(권한이 없다면) ExceptionTranslationFilter가 이 class의 handle()을 호출한다!
@Component
public class AjaxAccessDeniedHandler implements AccessDeniedHandler {
    // ExceptionTranslationFilter로부터 인가예외(accessDeniedException)를 파라미터로 받음 ( 인증예외를 파라미터로 받는 AjaxLoginAuthenticationEntryPoint와 구분할 것!)
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_FORBIDDEN,"Access is denied!");
    }
}
