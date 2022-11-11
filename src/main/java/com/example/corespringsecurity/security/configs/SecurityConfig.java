package com.example.corespringsecurity.security.configs;

import com.example.corespringsecurity.security.common.FormAuthenticationDetailsSource;
import com.example.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import com.example.corespringsecurity.security.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;


@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    /**
     * Spring에서 Bean을 등록하는 방식 소개
     * https://mangkyu.tistory.com/75
     *
     *  @Bean : 개발자가 직접 제어가 불가능한 외부 라이브러리등을 Bean 으로 만들려할때 사용된다.
     *  @Configuration 설정된 class 안의 @Bean 어노테이션이 붙은 메소드가 return하는 class를 Bean으로 등록
     *      등록되는 Bean의 이름은 메소드명을 default로 한다.
     *
     *
     */

    // Customize 한 FormAuthenticationDetailsSource bean 등록
    // 왜 FormAuthenticationDetailSource 를 주입하지 않고 interface로 주입해도 FormAuthenticationDetailSource가 주입되는거지?
//            successHandler 로 마찬가지구 ..
    private final AuthenticationDetailsSource authenticationDetailsSource;
    private final AuthenticationSuccessHandler authenticationSuccessHandler;
    private final AuthenticationFailureHandler authenticationFailureHandler;
//    private final AccessDeniedHandler accessDeniedHandler;


    // 왜 CustomAccessDeniedHandler class 에서 직접 에러페이지를 세팅하지 않는거지 ?
    // CustomAccessDeniedHandler 는 왜 private final로 의존주입을 받지 않고 bean으로 설정하는 거지 ?
//    @Bean으로 한 이유는 exception핸들러에 추가적으로 setter를 사용해야 했기 때문에 @Bean으로 등록한것이고
//    @Autowired나 private final로 의존주입을 한 경우는 추가작업 없이 의존성 주입만 하면 되기 때문
    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }

    // Customize 한 AuthenticationProvider bean 등록, SpringSecurity가 이 Provider를 참조해서 인증처리를 하게 됨
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
        return new CustomAuthenticationProvider();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/","/users","user/login/**","/login*").permitAll()
//                .antMatchers("/css/**","/js/**","/images/**","/webjars/**","/favicon.*","/*/icon-*").permitAll() // WebIgnore 설정으로 변경
                // prefix ROLE_ 이 붙음
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
                .formLogin()
                .loginPage("/login") // custom login page
                .loginProcessingUrl("/login_proc")  // login.html에 정의된 action 값과 동일하게 정의해야함
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(authenticationSuccessHandler)
                .failureHandler(authenticationFailureHandler)
                .permitAll(); // 로그인 페이지는 permitAll

        http
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());


        return http.build();
    }

// DB에서 사용자 직접 조회할 예정이기 때문에 주석처리
    // IN-MEMORY 방식  user 생성
//    @Bean
//    public UserDetailsManager user(){
//        String password = passwordEncoder().encode("1111");
//        UserDetails user = User.builder()
//                .username("user")
//                .password(password)
//                .roles("USER").build();
//        UserDetails manager = User.builder()
//                .username("manager")
//                .password(password)
//                .roles("MANAGER","USER").build();
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password(password)
//                .roles("ADMIN","USER","MANAGER").build();
//        return new InMemoryUserDetailsManager(user,manager,admin);
//    }

    // 평문인 비밀번호 암호화 해주는 encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // WebIgnore 설정: js,css,image 파일 등 보안 필터를 적용할 필요가 없는 리소스 설정 , 보안 filter 자체를 거치지 않음.
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
//         web : WebSecurity class 객체가 들어옴
        return web -> {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
            web.ignoring().antMatchers("/favicon.ico", "/resources/**", "/error");
        };
//        아래 식과 같은 표현 (alt+enter로 lamda 식으로 변경 가능)
//        return new WebSecurityCustomizer() {
//            @Override
//            public void customize(WebSecurity web) {
//                web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
//            }
//        };

    }
}
