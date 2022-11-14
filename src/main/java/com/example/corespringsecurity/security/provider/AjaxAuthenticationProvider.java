package com.example.corespringsecurity.security.provider;

import com.example.corespringsecurity.security.common.FormWebAuthenticationDetails;
import com.example.corespringsecurity.security.service.AccountContext;
import com.example.corespringsecurity.security.token.AjaxAuthenticationToken;
import lombok.NoArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

// AuthenticationProvider class를 구현하는 Provider class는 authenticate(),support()를 구현해야 한다.
// Provider class는 실제 인증처리를 하는 클래스, ProviderManager로부터 인증처리를 하라고 위임받음.
@RequiredArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {

//    @Autowired
//    private UserDetailsService userDetailsService;
//    @Autowired
//    private PasswordEncoder passwordEncoder;

    private final UserDetailsService userDetailsService;

    private final PasswordEncoder passwordEncoder;

    // ProviderManager로부터 인증객체 전달받음 (parameter). 이 인증객체는 Client가 입력한 or 전달한 값(id, pw, details..)를 가지고 있음
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // client가 전송한 값 꺼내오기
        String loginId = authentication.getName();
        String password= (String)authentication.getCredentials();
        // 반환 타입이 원래는 UserDetails이지만 customize한 클래스로 변경
        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(loginId);
        if(!passwordEncoder.matches(password, accountContext.getPassword())){
            throw new BadCredentialsException("Invalid Password");
        }
//        String secretKey = ((FormWebAuthenticationDetails)authentication.getDetails()).getSecretKey();
//        if(secretKey == null || !secretKey.equals("secret")){
//            throw new IllegalArgumentException("Invalid Secret");
//        }
        // 실제 사용자 정보(username, 권한정보)를 담아서 인증객체 return
        return new AjaxAuthenticationToken(accountContext.getAccount(),null,accountContext.getAuthorities());
    }

    // 올바른 token class type 이어야 이 provider가 동작하도록 하는 class
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}
