package com.substring.auth.config;

import com.substring.auth.Security.JwtAuthenticationFilter;
import com.substring.auth.Security.OAuth2SuccessHandler;
import com.substring.auth.dtos.ApiError;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tools.jackson.databind.ObjectMapper;

import java.lang.reflect.Array;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

@Configuration
@EnableWebSecurity
public class SecurityConfig {


    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final AuthenticationSuccessHandler successHandler;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter, AuthenticationSuccessHandler successHandler) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.successHandler = successHandler;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

         http.csrf(AbstractHttpConfigurer::disable)
                 .cors(Customizer.withDefaults())
                 .sessionManagement(sm->sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                 .authorizeHttpRequests(authorizeHttpRequests ->
                        authorizeHttpRequests
                                .requestMatchers(AppConstants.AUTH_PUBLIC_URLS)
                                .permitAll()
                                .anyRequest()
                                .authenticated()
                )
                 .oauth2Login( oauth2->
                                 oauth2.successHandler(successHandler)
                                         .failureHandler(null)
                         )
                 .logout(AbstractHttpConfigurer::disable)
                 .exceptionHandling(ex-> ex.authenticationEntryPoint(((request, response, e) ->{
                     // error message for client
//                     e.printStackTrace();
                     response.setStatus(401);
                     response.setContentType("application/json");
                     String message = e.getMessage();
                     String error = (String) request.getAttribute("error");
                     if(error!=null){
                          message = error;
                     }

//                     Map<String,Object> errorMap= Map.of(
//                             "message",message,
//                             "statusCode", 401);
                     var apiError= ApiError.of(HttpStatus.UNAUTHORIZED.value(),
                             "Unauthorized Access !!",
                             message,request.getRequestURI(),
                             null);
                     var objectMapper = new ObjectMapper();
                     response.getWriter().write(objectMapper.writeValueAsString(apiError));


                 })))
                 .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration)
    {
        return  configuration.getAuthenticationManager();
    }

//    @Bean
//    public UserDetailsService userDetailsService(){
//        User.UserBuilder userBuilder= User.withDefaultPasswordEncoder();
//
//        UserDetails user1 = userBuilder.username("nishant").password("abc123").roles("ADMIN").build();
//        UserDetails user2 = userBuilder.username("vishal").password("abc").roles("ADMIN").build();
//        UserDetails user3 = userBuilder.username("nikhil").password("abc12").roles("USER").build();
//
//        return new  InMemoryUserDetailsManager(user1);
//    }

    public CorsConfigurationSource corsConfigurationSource(
            @Value("${app.cors.front-end-url}") String corsUrls
    ){
        String[] split =corsUrls.trim().split(",");
        var config= new CorsConfiguration();
        config.setAllowedOrigins(Arrays.asList(split));
        config.setAllowedMethods(List.of("GET","POST","PUT","DELETE","OPTIONS","PATCH"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        var source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**",config);

    return source;

    }


}