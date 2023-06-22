package com.example.securitytest.service;

import com.example.securitytest.config.JwtToken;

public interface UserService {

    public JwtToken login(String email, String password);
}
