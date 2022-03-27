package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
                /*.loginPage("/loginPage") //사용자 정의 로그인 페이지
                .defaultSuccessUrl("/") //로그인 성공 후 이동 페이지
                .failureUrl("/loginPage") //로그인 실패 후 이동 페이지
                .usernameParameter("userId") //아이디 파라미터명 설정
                .passwordParameter("passwd") //패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc") // 로그인 Form action url
                .successHandler(new AuthenticationSuccessHandler() { //로그인 성공 후 Handler
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication : "+authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { //로그인 실패 후 Handler
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception : "+exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll()*/
        ;

        http
                .logout() //로그아웃 처리
                .logoutUrl("/logout") //로그아웃 처리 URL
                .logoutSuccessUrl("/login") //로그아웃 성공 후 이동 페이
                .addLogoutHandler(new LogoutHandler() { //로그아웃 핸들러
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { //로그아웃 성공 후 핸들러
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me") //로그아웃 후 쿠키 삭제

        .and()
                .rememberMe()
                //.rememberMeParameter("remember")//기본 파라미터명은 remember-me
                //.tokenValiditySeconds(3600) //Default는 14일
                .userDetailsService(userDetailsService())
        ;

        http
                .sessionManagement() //세션 관리기능 작동
                .maximumSessions(1) //최대 허용가능 세션 수 , -1은 무제한 세션 허용
                .maxSessionsPreventsLogin(true) //동시로그인 차단, false : 기존 세션 만료(default)
        ;

        http
                .sessionManagement()
                .sessionFixation().changeSessionId() //기본값, none/migrateSession/newSession
        ;

        http
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED) //기본값, Always/Never/Stateless
        ;

    }
}
