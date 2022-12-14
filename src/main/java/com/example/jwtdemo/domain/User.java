package com.example.jwtdemo.domain;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.Collection;
import java.util.UUID;

import static javax.persistence.GenerationType.AUTO;

@AllArgsConstructor
@Data
@Entity
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = AUTO)
    private Long id;
    private String name;
    private String username;
    private String password;
    @ManyToMany(fetch = FetchType.EAGER) //eager always loads user's roles when user is loaded
    private Collection<Role> roles = new ArrayList<>();
}
