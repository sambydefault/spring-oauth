package com.boot.auth.oauthserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.token.KeyBasedPersistenceTokenService;
import org.springframework.security.core.token.TokenService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@EnableWebSecurity
@Configuration
public class WebConfig extends WebSecurityConfigurerAdapter {

   @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(10);
    }

   @Bean
    UserDetailsService userDetailsServiceCustom(){
        System.out.println("configured the user");
        UserDetails userDetails = User.withUsername("test").password(passwordEncoder().encode("password"))
                .authorities("ROSETTA_ADMIN").build();
        return new InMemoryUserDetailsManager(userDetails);
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        System.out.println("setting up authentication manager bean");
        return super.authenticationManagerBean();
    }

    //auth manager builder

    /*@Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        System.out.println("Manager builder");
        auth.userDetailsService(userDetailsServiceCustom()).passwordEncoder(passwordEncoder());
    }*/

    /*@Override
    protected void configure(HttpSecurity http) throws Exception {
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and().authorizeRequests().antMatchers("/login","/auth/login").permitAll()
                .antMatchers("/api/**").authenticated()
                .and().formLogin();
        //.loginPage("/auth/login").permitAll();
    }*/
}
