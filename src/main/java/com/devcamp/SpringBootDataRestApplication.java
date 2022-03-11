package com.devcamp;

import java.util.HashSet;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.devcamp.entity.AppUser;
import com.devcamp.entity.Role;
import com.devcamp.repos.RoleRepository;
import com.devcamp.service.IAppUserService;

@SpringBootApplication
public class SpringBootDataRestApplication {

    @Autowired
    private RoleRepository roleRepository;

    @Value("${app.secret.jwt}")
    private String jwtSecret;

    public static void main(String[] args) {
	SpringApplication.run(SpringBootDataRestApplication.class, args);
    }

    @Bean
    CommandLineRunner run(IAppUserService userService) throws Exception {
	return args -> {

	    var ADMIN = roleRepository.save(new Role("ROLE_ADMIN"));
	    var USER = roleRepository.save(new Role("ROLE_USER"));

	    var lamtanloc = new AppUser(null, "lamtanloc2", new BCryptPasswordEncoder().encode("12345"),
		    new HashSet<>());
	    lamtanloc.getRole().add(ADMIN);
	    lamtanloc.getRole().add(USER);

	    userService.saveUser(lamtanloc);

	};

    }

    @Bean
    BCryptPasswordEncoder bCryptPasswordEncoder() {
	return new BCryptPasswordEncoder();
    }

}
