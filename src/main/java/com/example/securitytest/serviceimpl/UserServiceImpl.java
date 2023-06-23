package com.example.securitytest.serviceimpl;

import com.example.securitytest.config.JwtToken;
import com.example.securitytest.config.JwtTokenProvider;
import com.example.securitytest.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

    private final BCryptPasswordEncoder encoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final JwtTokenProvider jwtTokenProvider;

    public UserServiceImpl(BCryptPasswordEncoder encoder, AuthenticationManagerBuilder authenticationManagerBuilder, JwtTokenProvider jwtTokenProvider) {
        this.encoder = encoder;
        this.authenticationManagerBuilder = authenticationManagerBuilder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public JwtToken login(String email, String password) {
        try {
            log.info("loginService========================");
            UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(email, password);
            log.info("service1");
            log.info("email : " + email);
            log.info("password : " + password);
            log.info(authenticationToken.toString());
            Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);
            log.info("service2");
            log.info("authentication : " + authentication.toString());
            JwtToken token = jwtTokenProvider.generateToken(authentication);
            log.info("token : " + token);
            return token;

        } catch (AuthenticationException e) {
            log.info("에러!!! ");
            log.error("Authentication failed: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
}
