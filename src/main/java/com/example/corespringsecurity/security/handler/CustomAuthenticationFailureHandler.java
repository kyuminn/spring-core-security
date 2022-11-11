package com.example.corespringsecurity.security.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
@Slf4j
// 인증을 시도하다가 예외가 발생한 경우 인증 filter가 그 예외를 받아서 이 class에게 넘겨준다.
// 인증을 만약에 성공했는데 권한이 없는 경우(인가처리가 안되어 있는 경우는)인가예외가 발생하고, 인가예외는 인증필터가 아닌 ExceptionTranslationFilter가 받아 accessDeniedHandler를 호출해 처리한다.
public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    // 예외 발생시 여기서 catch 해서 message client 단에 보여주기
    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        logger.info("CustomAuthenticationFailureHandler!");
        String errorMessage = "Invalid Username or Password"; // default
        if (exception instanceof BadCredentialsException){
            errorMessage = "Invalid Username or Password";
        }else if(exception instanceof InsufficientAuthenticationException){
            errorMessage="Invalid Secert Key";
        }

        // loginController에게 넘겨준다. queryString값은 controller단에서 RequestParam으로 받는다.
        // Spring Security는 아래 String을 전체 url로 인식하기 때문에 설정파일에서 /login* 경로에 대한 permitAll 을 해줘야 한다.
        setDefaultFailureUrl("/login?error=true&exception="+errorMessage);

        super.onAuthenticationFailure(request,response,exception);
    }
}
