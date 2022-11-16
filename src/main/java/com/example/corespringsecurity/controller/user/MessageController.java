package com.example.corespringsecurity.controller.user;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class MessageController {

    @GetMapping(value="/messages")
    public String message(){
        return "user/messages";
    }

    @GetMapping(value = "/api/messages")
    @ResponseBody // json 형식으로 문자열 그대로 응답 
    public String apiMessage(){
        return "messages ok";
    }
}
