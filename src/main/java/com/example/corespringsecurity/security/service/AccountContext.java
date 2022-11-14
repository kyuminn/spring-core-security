package com.example.corespringsecurity.security.service;

import com.example.corespringsecurity.domain.Account;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

// user 계정(account)클래스를 담고 있는 AccountContext class
public class AccountContext extends User {

    @Getter
    private final Account account;

    // 객체의 불변성을 위해 setter 함수 지양.
    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUsername(), account.getPassword(), authorities);
        this.account = account;
    }
}
