package com.example.TestSpringJWT.presentation;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@ResponseBody // 웹이 아닌 특정 문자열 데이터를 반환
public class MainController {

    @GetMapping("/")
    public String mainP() {

        return "Main Controller";
    }
}
