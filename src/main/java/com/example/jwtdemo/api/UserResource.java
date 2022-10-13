package com.example.jwtdemo.api;

import com.example.jwtdemo.domain.Role;
import com.example.jwtdemo.domain.User;
import com.example.jwtdemo.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.util.List;

@RequestMapping("/api")
@RequiredArgsConstructor
@RestController
public class UserResource {
    private final UserService userService;

    @GetMapping("/users")
    public ResponseEntity<List<User>> getUsers(){
        return ResponseEntity.ok().body(userService.getUsers());
    }

    @PostMapping("/user/save")
    public ResponseEntity<User> saveUser(@RequestBody User user){
        return ResponseEntity.created(URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/user/save").toUriString()))
                .body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role){
        return ResponseEntity.created(URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("api/role/save").toUriString()))
                .body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser/{username}/{rolename}")
    public ResponseEntity<?> saveRole(@PathVariable String username, @PathVariable String rolename){
        userService.addRoleToUser(username, rolename);
        return ResponseEntity.ok().build();
    }
}
