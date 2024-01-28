package com.app;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true) //for @secured & @roleAllowed resp.
public class MySpringSecurityProjectWithOauth2KeycloakBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(MySpringSecurityProjectWithOauth2KeycloakBackendApplication.class, args);
	}

}
