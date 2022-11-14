package com.example.corespringsecurity.security.configs;

import com.example.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import com.example.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import com.example.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import com.example.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import com.example.corespringsecurity.security.service.CustomUserDetailsService;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Order(0)
@RequiredArgsConstructor
public class AjaxSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    // to-do :SecurityConfig required a single bean, but 2 were found:
    private final AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler;
    private final AjaxAuthenticationFailureHandler ajaxAuthenticationFailureHandler;

    // Spring security가 인증처리를 할때 이 provider를 사용해서 인증처리를 함
    // RequriedArgsConstructor 방식으로 바꿈!
//    @Bean
//    public AjaxAuthenticationProvider ajaxAuthenticationProvider(CustomUserDetailsService userDetailsService, PasswordEncoder passwordEncoder){
//        return new AjaxAuthenticationProvider(userDetailsService,passwordEncoder);
//    }

    @Bean
    public AjaxAuthenticationProvider ajaxAuthenticationProvider(){
        return new AjaxAuthenticationProvider(userDetailsService,passwordEncoder);
    }


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .antMatcher("/api/**") // api로 시작하는 경로에 한해서만 AjaxSecurityConfig class가 동작하도록
                .authorizeRequests()
                .anyRequest().authenticated();

        AuthenticationManager authenticationManager = authenticationManager(http.getSharedObject(AuthenticationConfiguration.class));
        http
                .addFilterBefore(ajaxLoginProcessingFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);// 뒤에 있는 필터 앞에 위치하도록 하는 method
        http.csrf().disable();
        return http.build();
    }

    // Ajax 방식 로그인 시 작동하는 필터 추가
    // 이거 private final 해도 되나? filter 클래스 위에 @Component 해보고 ?
    // -> Magager 설정 해야 해서 안될 듯..
    @Bean
    public AjaxLoginProcessingFilter ajaxLoginProcessingFilter(AuthenticationManager authenticationManager){
        AjaxLoginProcessingFilter ajaxLoginProcessingFilter =
                new AjaxLoginProcessingFilter();
        ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager);
        ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler);
        ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler);
        return ajaxLoginProcessingFilter;
    }

    // 왜 form 방식에서는 customAuthenticationProvider bean 등록만 해줘도 인식하는데 ajax에서는 인식을 못하고 추가적으로
    // provider를 등록해줘야하지 ?
    // https://www.inflearn.com/questions/667022 읽어보기..
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        ProviderManager authenticationManager = (ProviderManager) authenticationConfiguration.getAuthenticationManager();
        authenticationManager.getProviders().add(ajaxAuthenticationProvider());
        return authenticationManager;
    }
}
