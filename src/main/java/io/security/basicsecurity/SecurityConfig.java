package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //인증 정책
        http
                .formLogin();

        http
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false);

        //인가 정책
        http
                .authorizeRequests()
                .anyRequest().authenticated();
    }
}
