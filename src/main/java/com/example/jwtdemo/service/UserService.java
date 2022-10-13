package com.example.jwtdemo.service;

import com.example.jwtdemo.domain.Role;
import com.example.jwtdemo.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String roleName);
    User getUser(String username);
    List<User> getUsers();
}
