package com.example.corespringsecurity.security.configs;

import com.example.corespringsecurity.security.common.FormAuthenticationDetailsSource;
import com.example.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import com.example.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import com.example.corespringsecurity.security.handler.CustomAuthenticationFailureHandler;
import com.example.corespringsecurity.security.handler.CustomAuthenticationSuccessHandler;
import com.example.corespringsecurity.security.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@EnableWebSecurity
@RequiredArgsConstructor
@Order(1)
public class SecurityConfig {
    /**
     * Spring?????? Bean??? ???????????? ?????? ??????
     * https://mangkyu.tistory.com/75
     *
     *  @Bean : ???????????? ?????? ????????? ???????????? ?????? ????????????????????? Bean ?????? ??????????????? ????????????.
     *  @Configuration ????????? class ?????? @Bean ?????????????????? ?????? ???????????? return?????? class??? Bean?????? ??????
     *      ???????????? Bean??? ????????? ??????????????? default??? ??????.
     *
     *
     */

    // Customize ??? bean ??????
    // Spring DI??? ??????????????? ???????????? ?????? ????????? ????????? ??????
    //????????? ??????????????? ???????????? ???????????? ?????? ????????? ???????????? ????????? ?????????
    // ?????? ??????????????? ???????????? ????????? bean??? ???????????? ??????????????? ??? class??? bean?????? ?????????

    // ????????? AuthenticationDetailSource??? ??????????????? FormAuthenticationDetailsSource bean??? ???????????? ?????????.

            // private final ?????? DI ?????? bean ????????? ????????? ?????? ?
            // ==>???????????? ????????? class??????. ?????? ??????????????? ???????????? ???????????? ????????? (??? : customAuthenticationSuccessHandler)
    private final AuthenticationDetailsSource authenticationDetailsSource;
    private final CustomAuthenticationSuccessHandler formAuthenticationSuccessHandler;
    private final CustomAuthenticationFailureHandler formAuthenticationFailureHandler;
//    private final AccessDeniedHandler accessDeniedHandler;


    // ??? CustomAccessDeniedHandler class ?????? ?????? ?????????????????? ???????????? ???????????? ?
    // CustomAccessDeniedHandler ??? ??? private final??? ??????????????? ?????? ?????? bean?????? ???????????? ?????? ?
//    @Bean?????? ??? ????????? exception???????????? ??????????????? setter??? ???????????? ?????? ????????? @Bean?????? ??????????????????
//    @Autowired??? private final??? ??????????????? ??? ????????? ???????????? ?????? ????????? ????????? ?????? ?????? ??????
    @Bean
    public AccessDeniedHandler accessDeniedHandler(){
        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
        accessDeniedHandler.setErrorPage("/denied");
        return accessDeniedHandler;
    }




    // Customize ??? AuthenticationProvider bean ??????, SpringSecurity??? ??? Provider??? ???????????? ??????????????? ?????? ???
    @Bean
    public CustomAuthenticationProvider customAuthenticationProvider(){
        return new CustomAuthenticationProvider();
    }
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/","/users","user/login/**","/login*").permitAll()
//                .antMatchers("/css/**","/js/**","/images/**","/webjars/**","/favicon.*","/*/icon-*").permitAll() // WebIgnore ???????????? ??????
                // prefix ROLE_ ??? ??????
                .antMatchers("/mypage").hasRole("USER")
                .antMatchers("/messages").hasRole("MANAGER")
                .antMatchers("/config").hasRole("ADMIN")
                .anyRequest().authenticated()
            .and()
                .formLogin()
                .loginPage("/login") // custom login page
                .loginProcessingUrl("/login_proc")  // login.html??? ????????? action ?????? ???????????? ???????????????
                .authenticationDetailsSource(authenticationDetailsSource)
                .defaultSuccessUrl("/")
                .successHandler(formAuthenticationSuccessHandler)
                .failureHandler(formAuthenticationFailureHandler)
                .permitAll(); // ????????? ???????????? permitAll
        http
                .exceptionHandling()
                .accessDeniedHandler(accessDeniedHandler());
        //Spring security????????? post, delete ???????????? ???????????? ?????? csrf token??? ????????? ?????????. ??????????????? ?????? disable ?????? ???.
//        http.csrf().disable();


        return http.build();
    }

// DB?????? ????????? ?????? ????????? ???????????? ????????? ????????????
    // IN-MEMORY ??????  user ??????
//    @Bean
//    public UserDetailsManager user(){
//        String password = passwordEncoder().encode("1111");
//        UserDetails user = User.builder()
//                .username("user")
//                .password(password)
//                .roles("USER").build();
//        UserDetails manager = User.builder()
//                .username("manager")
//                .password(password)
//                .roles("MANAGER","USER").build();
//        UserDetails admin = User.builder()
//                .username("admin")
//                .password(password)
//                .roles("ADMIN","USER","MANAGER").build();
//        return new InMemoryUserDetailsManager(user,manager,admin);
//    }

    // ????????? ???????????? ????????? ????????? encoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // WebIgnore ??????: js,css,image ?????? ??? ?????? ????????? ????????? ????????? ?????? ????????? ?????? , ?????? filter ????????? ????????? ??????.
    @Bean
    public WebSecurityCustomizer webSecurityCustomizer(){
//         web : WebSecurity class ????????? ?????????
        return web -> {
            web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
            web.ignoring().antMatchers("/favicon.ico", "/resources/**", "/error");
        };
//        ?????? ?????? ?????? ?????? (alt+enter??? lamda ????????? ?????? ??????)
//        return new WebSecurityCustomizer() {
//            @Override
//            public void customize(WebSecurity web) {
//                web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations());
//            }
//        };

    }
}
