package com.devcamp.api;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@CrossOrigin(maxAge = -1, value = "*")
@RequestMapping("/api/v1")
public class UserApiController implements UserApi {

    @GetMapping("/user")
    @Override
    public String getUsers() {
        return new String("Hello my name is Loc");
    }
}
