package com.example.corespringsecurity.security.service;

import com.example.corespringsecurity.domain.Account;
import com.example.corespringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
/**
 *  CustomAuthenticationProvider를 구현하지 않은 상태에서
 *  CustomUserDetailsService를 SecurityConfig 파일에 등록하지 않아도 자동으로 이 서비스 파일을 이용하는 이유가 뭐지 ..?
 *  -> 이유 : 스프링 시큐리티에서는 내부적으로 DaoAuthenticationProvider 클래스가 CustomUserDetailsService를 호출해서 인증처리 및 비밀번호 체크
 *  출처 : https://www.inflearn.com/questions/350921
 *  이후에 CustomAuthenticationProvider가 CustomUserDetailsService를 참조 하도록 구현할 수 있음.
 *
 *  cf) DaoAuthenticationProvider는 default 값으로 InMemoryUserDetailsManager(UserDetailsService의 구현체)을 참조하는 듯
 */



@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Account account = userRepository.findByUsername(username);

        if(account==null){
            throw new UsernameNotFoundException("UsernameNotFoundException!");
        }
        //GrantedAuthority = interface 이므로 , 구현체를 넣어도 됨
        List<GrantedAuthority> roles= new ArrayList<>();
        roles.add(new SimpleGrantedAuthority(account.getRole()));
        AccountContext accountContext = new AccountContext(account,roles);
        System.out.println("@@@@@@@@@@@@@@@@@@@@@@");

        // AccountContext가 User class를 상속받고 ,Users는 UserDetails의 구현체
        return accountContext;
    }
}
