package com.example.corespringsecurity.security.common;

import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;

/**
 * FormWebAuthenticationDetails 객체를 생성하는 class
 * SecurityConfig 설정 클래스에서 bean으로 등록
 */
@Component
public class FormAuthenticationDetailsSource implements AuthenticationDetailsSource<HttpServletRequest,FormWebAuthenticationDetails> {

    @Override
    public FormWebAuthenticationDetails buildDetails(HttpServletRequest request) {
        return new FormWebAuthenticationDetails(request);
    }
}
