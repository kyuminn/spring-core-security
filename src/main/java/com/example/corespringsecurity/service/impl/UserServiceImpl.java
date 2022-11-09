package com.example.corespringsecurity.service.impl;

import com.example.corespringsecurity.domain.Account;
import com.example.corespringsecurity.repository.UserRepository;
import com.example.corespringsecurity.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
@Service("userService")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Transactional
    @Override
    public void createUser(Account account) {
        userRepository.save(account);
    }
}
