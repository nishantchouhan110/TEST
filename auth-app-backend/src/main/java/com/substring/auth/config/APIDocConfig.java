package com.substring.auth.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info =@Info(
                title = "Auth Application build by Nishant Chouhna",
                description = "Genric auth app that can be used with any application ",
                contact = @Contact(
                        name = "Nishant Chouhan",
                        url = "http://substring.com",
                        email = "nishantchouhan110@gmail.com"
                ),
                version = "1.0",
                summary = "this app is very useful if you dont want create auth app from scratch."

        ),
        security ={
                @SecurityRequirement(
                        name = "bearerAuth"
                )
        }

)
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT"

)
public class APIDocConfig {


}
