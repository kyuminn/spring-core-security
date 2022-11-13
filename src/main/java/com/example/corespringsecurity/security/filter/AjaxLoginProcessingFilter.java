package com.example.corespringsecurity.security.filter;

import com.example.corespringsecurity.domain.AccountDto;
import com.example.corespringsecurity.security.token.AjaxAuthenticationToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
// Ajax 방식 로그인 처리 필터 <====> UsernamePasswordAuthenticationFilter ( form 로그인 방식 인증 필터)
// 인증처리 관련 흐름 user request -> filter -> manager -> provider(getProviders()있음)
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {



    public AjaxLoginProcessingFilter() {
        // 사용자가 /api/login이라고 요청했을 때 이 filter가 작동하도록 구성
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        // ajax 인지 확인
        if(!isAjax(request)){
            throw new IllegalStateException("Ajax Authentication is not supported");
        }
        // json 방식으로 온 사용자 요청 정보를 객체로 추출
        // HttpServletRequest의 getReader() = post로 보낸 application/json 타입의 http body를 읽어오는 method
        AccountDto accountDto = new ObjectMapper().readValue(request.getReader(), AccountDto.class);

        // 읽어온 정보 null 값인지 확인
        if(StringUtils.isEmpty(accountDto.getUsername())|| StringUtils.isEmpty(accountDto.getPassword())){
            throw new IllegalArgumentException("Username or Password is empty");
        }

        // ajax인증전용 토큰 생성 (사용자가 입력한 id와 pw 바탕으로)
        AjaxAuthenticationToken token = new AjaxAuthenticationToken(accountDto.getUsername(),accountDto.getPassword());
        // manager에게 인증처리 하도록 함
        return getAuthenticationManager().authenticate(token);
    }

    private boolean isAjax(HttpServletRequest request) {
        if("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))){
            return true;
        }
        return false;
    }
}
