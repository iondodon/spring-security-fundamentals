package com.amdaris.ssf;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class DemoController {

    @GetMapping("/")
    @ResponseBody
    public String demo() {
        return "demo";
    }

}
