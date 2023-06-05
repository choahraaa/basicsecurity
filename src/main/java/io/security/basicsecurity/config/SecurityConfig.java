package io.security.basicsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Configuration
@EnableWebSecurity  //웹보안이 활성화되는 어노테이션
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authz) -> authz
                        .anyRequest().authenticated() //어떤 요청에도 인증받지 않으면 들어갈 수 없게 설정
                );
        http //우리가 원하는 id/pw 로그인 되도록 설정
                .formLogin()
                .loginPage("/loginPage") //사용자가 정의한 로그인 페이지 설정
                .defaultSuccessUrl("/") //로그인 성공 후 이동할 페이지 경로 설정
                .failureUrl("/login") //로그인 실패 후 이동할 페이지 경로 설정
                .usernameParameter("userId") //form 로그인 안에서 설정된 username 파라미터명 설정(커스텀 가능)
                .passwordParameter("passwd") //form 로그인 안에서 설정된 password 파라미터명 설정(커스텀 가능)
                .loginProcessingUrl("/login_proc") //로그인 form action url 설정 (기본값 /login)
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override  //익명함수로 successHandelr 생성
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication" + authentication.getName());
                        response.sendRedirect("/"); //성공 후 리다이렉트 설정
                    }
                }) //로그인 성공 이후에 호출될 핸들러
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception" + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                }) //로그인 실패 이후에 호출될 핸들러

        ;
        return http.build();
    }
}
