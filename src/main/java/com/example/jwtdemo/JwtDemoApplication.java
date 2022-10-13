package com.example.jwtdemo;

import com.example.jwtdemo.domain.Role;
import com.example.jwtdemo.domain.User;
import com.example.jwtdemo.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.ArrayList;

@Slf4j
@SpringBootApplication
public class JwtDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(JwtDemoApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    CommandLineRunner run(UserService userService) {
        return args -> {
            userService.saveRole(new Role(null, "ROLE_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_MANAGER"));
            userService.saveRole(new Role(null, "ROLE_SUPER_ADMIN"));
            userService.saveRole(new Role(null, "ROLE_USER1"));
            userService.saveRole(new Role(null, "ROLE_USER2"));

            userService.saveUser(new User(null, "Kobe Bryant", "KobeBryant@la", "lakers", new ArrayList<>()));
            userService.saveUser(new User(null, "Drew Brees", "DrewBrees@no", "saints", new ArrayList<>()));
            userService.saveUser(new User(null, "Andre Dawson", "AndreDawson@chi", "cubs", new ArrayList<>()));
            userService.saveUser(new User(null, "Tiger Woods", "TigerWoods@us", "golf", new ArrayList<>()));

            userService.addRoleToUser("KobeBryant@la", "ROLE_SUPER_ADMIN");
            userService.addRoleToUser("DrewBrees@no", "ROLE_ADMIN");
            userService.addRoleToUser("AndreDawson@chi", "ROLE_MANAGER");
            userService.addRoleToUser("TigerWoods@us", "ROLE_USER1");
            userService.addRoleToUser("TigerWoods@us", "ROLE_USER2");

            log.info("Users: {}", userService.getUsers());
        };
    }

}
