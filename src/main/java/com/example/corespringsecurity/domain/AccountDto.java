package com.example.corespringsecurity.domain;


import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class AccountDto {
    private String username;
    private String password;
    private String email;
    private int age;
    private String role;
}
