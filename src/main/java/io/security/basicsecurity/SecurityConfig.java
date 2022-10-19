package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

import javax.servlet.http.HttpSession;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //인증 정책
        http
                .formLogin()
//                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureForwardUrl("/login")
                //usernameParameter, passwordParameter, loginProcessingUrl 세 가지는 로그인 화면 UI 파라미터명과 맞춰야 한다.
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler((request, response, authentication) -> {
                    System.out.println("authentication : " + authentication.getName());
                    response.sendRedirect("/");
                })
                .failureHandler((request, response, exception) -> {
                    System.out.println("exception : " + exception.getMessage());
                    response.sendRedirect("/login");
                })
                .permitAll();

        http
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler((request, response, authentication) -> {
                    HttpSession session = request.getSession();
                    session.invalidate();
                })
                .logoutSuccessHandler((request, response, authentication) -> {
                    response.sendRedirect("/login");
                })
                .deleteCookies("remember-me")
        ;

        //인가 정책
        http
                .authorizeRequests()
                .anyRequest()
                .authenticated();
    }
}
