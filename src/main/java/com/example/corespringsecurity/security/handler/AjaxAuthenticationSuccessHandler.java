package com.example.corespringsecurity.security.handler;

import com.example.corespringsecurity.domain.Account;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
// 인증이 성공해서 Manager class로부터 인증 객체를 전달받아 이 successHandler 클래스가 동작한다
@Component
public class AjaxAuthenticationSuccessHandler implements AuthenticationSuccessHandler {
    
    private ObjectMapper objectMapper = new ObjectMapper();

    // 이 경우 parameter의 Authentication 객체는 Provider의 authenticate()가 return한 new AjaxAuthenticationToken 객체!
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        Account account = (Account) authentication.getPrincipal();

        response.setStatus(HttpStatus.OK.value());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        // objectMapper가 account 객체를 json 형식으로 변환해서 client 단에 response 해줌
        // ajax 방식이기 때문에 페이지를 디라이렉트 하는 것 보다는 인증이 완료된 객체 (데이터)자체를 응답하는 것이 더 적당.
        objectMapper.writeValue(response.getWriter(),account);
    }
}
