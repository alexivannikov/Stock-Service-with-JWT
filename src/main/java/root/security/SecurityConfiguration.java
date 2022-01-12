package root.security;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import root.security.jwt.JWTAuthFilter;

@Configuration
@AllArgsConstructor
@Slf4j
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    private final DbUserDetailsService dbUserDetailsService;
    private final JWTAuthFilter jwtAuthFilter;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(dbUserDetailsService);
    }

    @Override
    public void configure(HttpSecurity http) throws Exception{
        http
                .csrf().disable()
                .authorizeRequests().antMatchers("/stock-data/real-time").hasAnyAuthority("BASE", "PRO")
                .antMatchers("/stock-data/historical").hasAuthority("PRO")
                .and().authorizeRequests().antMatchers("/auth/**").permitAll()
                .and().authorizeRequests().anyRequest().authenticated()
                .and().httpBasic()
                .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManagerBean() {
        try {
            return super.authenticationManagerBean();
        } catch (Exception e) {
            log.error("Error creating authenticationManagerBean", e);
            throw new BeanCreationException("Error creating authenticationManagerBean");
        }
    }
}
