package io.security.corespringsecurity.security.configs;

import io.security.corespringsecurity.security.provider.CustomAuthenticationProvider;
import jakarta.websocket.Encoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private AuthenticationSuccessHandler customAuthenticationSuccessHandler;

    @Autowired
    private AuthenticationDetailsSource authenticationDetailsSource;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    /*@Bean
    public UserDetailsManager users() {

        String password = passwordEncoder().encode("1111");

        UserDetails user = User.builder()
                .username("user")
                .password(password)
                .roles("USER")
                .build();
        UserDetails manager = User.builder()
                .username("manager")
                .password(password)
                .roles("MANAGER")
                .build();
        UserDetails admin = User.builder()
                .username("admin")
                .password(password)
                .roles("ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, manager, admin);
    }*/

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()
                .requestMatchers("/", "/users").permitAll()
                .requestMatchers("/mypage").hasRole("USER")
                .requestMatchers("/messages").hasRole("MANAGER")
                .requestMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated();

        http
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login_proc") //login.html의 form action tag
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(customAuthenticationSuccessHandler)
                .permitAll() //로그인 하지 않은 사용자도 접근이 가능해야 하기 때문에
        ;
        return http.build();
    }

    /**
     * WebIgnore
     * : js / css / image 파일 등 보안 필터를 적용할 필요가 없는 리소스를 설정
     */
    @Bean
    WebSecurityCustomizer webSecurityCustomizer() {
        return web -> {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
            //최초 로그인시 /error로 redirect 되는 문제 해결
            web.ignoring().requestMatchers("/favicon.ico", "/resources/**", "/error");
        };
    }

    /**
     * CustomUserDetailsService
     * : AuthenticationManagerBuilder, UserDetailsService 버전 업데이트 후 변경
     */
    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration authConfiguration) throws Exception {
        return authConfiguration.getAuthenticationManager();
    }

    /**
     * CustomAuthenticationProvider
     */
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider() {
        return new CustomAuthenticationProvider();
    }

}
