package com.boot.auth.oauthserver.Resources;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class Test {
    @RequestMapping("/auth/login")
    public String getTest(){
        return "login";
    }
}
