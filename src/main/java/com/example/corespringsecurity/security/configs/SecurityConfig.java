package com.example.corespringsecurity.security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;


@EnableWebSecurity
public class SecurityConfig {
    // @Bean : 개발자가 직접 제어가 불가능한 외부 라이브러리등을 Bean 으로 만들려할때 사용된다.

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/").permitAll()
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
        // 아래 @Bean으로 선언한 passwordEncoder를 사용하는 예시 
        String password = passwordEncoder().encode("1111");
        UserDetails user = User.builder()
                .username("user")
                .password(password)
                .roles("USER").build();
        UserDetails manager = User.builder()
                .username("manager")
                .password(password)
                .roles("MANAGER").build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(password)
                .roles("ADMIN").build();
        return new InMemoryUserDetailsManager(user,manager,admin);
    }

    // 평문인 비밀번호 암호화 해주는 encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
