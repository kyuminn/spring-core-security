package com.example.corespringsecurity.security.configs;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


@EnableWebSecurity
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

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/","/users").permitAll()
//                .antMatchers("/css/**","/js/**","/images/**","/webjars/**","/favicon.*","/*/icon-*").permitAll() // WebIgnore 설정으로 변경
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
                .and()
                .formLogin();



        return http.build();
    }


    // IN-MEMORY 방식  user 생성
    @Bean
    public UserDetailsManager user(){
        String password = passwordEncoder().encode("1111");
        UserDetails user = User.builder()
                .username("user")
                .password(password)
                .roles("USER").build();
        UserDetails manager = User.builder()
                .username("manager")
                .password(password)
                .roles("MANAGER","USER").build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(password)
                .roles("ADMIN","USER","MANAGER").build();
        return new InMemoryUserDetailsManager(user,manager,admin);
    }

    // 평문인 비밀번호 암호화 해주는 encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // WebIgnore 설정: js,css,image 파일 등 보안 필터를 적용할 필요가 없는 리소스 설정 , 보안 filter 자체를 거치지 않음.
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
        return web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());

    }
}
