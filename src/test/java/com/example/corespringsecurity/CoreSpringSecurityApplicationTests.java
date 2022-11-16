package com.example.corespringsecurity;

import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;

import java.util.Arrays;

@SpringBootTest
@RequiredArgsConstructor
class CoreSpringSecurityApplicationTests {

    private final ApplicationContext applicationContext;

    @Test
    void contextLoads() {
        if(applicationContext != null){
            String[] beanDefinitionNames = applicationContext.getBeanDefinitionNames();
            Arrays.stream(beanDefinitionNames).forEach(System.out::println);
        }
    }
}
