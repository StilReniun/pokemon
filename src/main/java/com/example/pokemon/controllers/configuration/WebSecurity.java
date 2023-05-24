package com.example.pokemon.controllers.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
public class WebSecurity extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.authorizeRequests()
                .antMatchers("/css/**", "/imagenes/**", "/js/**", "/", "/principal", "/home", "/inicio", "/logeo", "/login","/rest/**")
                .permitAll()
                .antMatchers("/aquatics/tolistAquatic").hasAnyRole("ADMIN","LECTOR","CREADOR","EDITOR","DEPURADOR")
                .antMatchers("/aquatics/nuevo").hasAnyRole("ADMIN","CREADOR")
                .antMatchers("/aquatics/guardar").hasAnyRole("ADMIN","CREADOR","EDITOR")
                .antMatchers("/aquatics/actualizar/**").hasAnyRole("ADMIN","EDITOR")
                .antMatchers("/aquatics/eliminar/**").hasAnyRole("ADMIN","DEPURADOR")

                .antMatchers("/fires/tolistFire").hasAnyRole("ADMIN","LECTOR","CREADOR","EDITOR","DEPURADOR")
                .antMatchers("/fires/nuevo").hasAnyRole("ADMIN","CREADOR")
                .antMatchers("/fires/guardar").hasAnyRole("ADMIN","CREADOR","EDITOR")
                .antMatchers("/fires/actualizar/**").hasAnyRole("ADMIN","EDITOR")
                .antMatchers("/fires/eliminar/**").hasAnyRole("ADMIN","DEPURADOR")


                .anyRequest().authenticated()
                .and().formLogin().loginPage("/login").defaultSuccessUrl("/bienvenida", true).permitAll()
                .and().logout()
                .permitAll();

    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {

        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        auth.inMemoryAuthentication().withUser("admin").password(encoder.encode("admin")).roles("ADMIN").and()
                .withUser("jorge").password(encoder.encode("jorge")).roles("LECTOR").and()
                .withUser("maria").password(encoder.encode("maria")).roles("CREADOR", "LECTOR").and()
                .withUser("elena").password(encoder.encode("elena")).roles("LECTOR","DEPURADOR").and()
                .withUser("ernesto").password(encoder.encode("ernesto")).roles("EDITOR","LECTOR").and();

    }



}
