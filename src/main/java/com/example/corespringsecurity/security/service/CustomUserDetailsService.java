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

// CustomUserDetailsService를 SecurityConfig 파일에 등록하지 않아도 자동으로 이 서비스 파일을 이용하는 이유가 뭐지 ..?
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
