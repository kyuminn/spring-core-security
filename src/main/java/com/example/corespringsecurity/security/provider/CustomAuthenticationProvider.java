package com.example.corespringsecurity.security.provider;

import com.example.corespringsecurity.security.service.AccountContext;
import com.example.corespringsecurity.security.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 사용자 요청 흐름                           authentication(사용자가 입력한 id,pw저장됨) 전달
 * UsernamePasswordAuthenticationFilter -------------------------------------------------> ProviderManager (List<Providers>를 가짐)
 * ProviderManager에서 default provider, parent provider 모두 탐색해서 해당 Provider class로 authentication 객체 전달
 * Provider class 에서는 인증객체에 담긴 username을 참조하는 service 클래스의 메소드(loadByUsername)를 호출, 사용자 정보가 있는지 확인 후 비밀번호 등 추가 인증 로직을 수행한다.
 * 그 이후 최종적인 인증객체를 생성하여 providerManager -> filter 순으로 다시 반환된다
 * filter에서는 최종 인증이 성공한 객체를 SecurityContext에 저장하는 등 인증 후에 필요한 비즈니스 로직을 수행한다.
 *
 *
 * Provider class: UserDetailsService의 구현체로부터 UserDetails 객체를 반환받고
 * 추가 검증 (비밀번호 검증 등)을 처리하는 곳
 *
 * Provider 가 return 하는 인증 객체는 Manager class에게 반환된다
 *
 *  return    UserDetails               AuthenticationToken
 * Service ----------------> Provider ---------------------> Manager
 *
 * AuthenticationManager의 구현체인 ProviderManager.java의 authentication()를 보면
 * 매니저가 여러개의 Provider들을 가지고 있는 것을 볼 수 있음
 *
 * 폼 인증에서 default provider는 DaoAuthenticationProvider 이고 이 클래스가 참조하는
 * UserDetailsService는 InMemoryUserDetailsManager 이다 (default)
 *
 * -token으로 끝나는 class :Authentication class
 */

//@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

//    private final UserDetailsService userDetailsService;
//    private final PasswordEncoder passwordEncoder;

    /**
     *
     * @param authentication the authentication request object.
     * @return
     * @throws AuthenticationException
     * 인증 관련 처리 메서드
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials(); //pw

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        if(!passwordEncoder.matches(password,accountContext.getAccount().getPassword())){
            throw new BadCredentialsException("BadCredentialException ! ! ! ");
        }
        System.out.println("CustomAuthenticationManager!");

        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(accountContext.getAccount(),null,accountContext.getAuthorities());


        return authenticationToken;
    }

    // 매개변수로 들어오는 authentication의 class 타입과 이 Provider class가 사용하려는 토큰값(Authentication) 의 타입이 일치할때
    // 이 Provider가 인증처리를 할수 있도록 조건을 검사
    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
