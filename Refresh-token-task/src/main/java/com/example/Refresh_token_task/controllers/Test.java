package com.example.Refresh_token_task.controllers;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/test")
public class Test {

    @GetMapping("/hello")
    public String hello(){
        return "Hello from a secure point";
    }
}
