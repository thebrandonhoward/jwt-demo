package com.example.jwtdemo.service;

import com.example.jwtdemo.domain.Role;
import com.example.jwtdemo.domain.User;
import com.example.jwtdemo.repo.RoleRepository;
import com.example.jwtdemo.repo.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Objects;

@RequiredArgsConstructor
@Service
@Slf4j
@Transactional
public class UserServiceImpl implements UserService, UserDetailsService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    private final PasswordEncoder passwordEncoder;

    /**
     * @param user
     * @return
     */
    @Override
    public User saveUser(User user) {
        log.info("saving {}", user);
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    /**
     * @param role
     * @return
     */
    @Override
    public Role saveRole(Role role) {
        log.info("saving {}", role);
        return roleRepository.save(role);
    }

    /**
     * @param username
     * @param roleName
     */
    @Override
    public void addRoleToUser(String username, String roleName) {
        log.info("adding role {} to user {}", roleName, username);

        User user = getUser(username);

        Role role = roleRepository.findRoleByName(roleName);

        user.getRoles().add(role);

        userRepository.save(user);

        log.info("added role {} to user {}", roleName, getUser(username));
    }

    /**
     * @param username
     * @return
     */
    @Override
    public User getUser(String username) {
        log.info("getting user {}", username);
        return userRepository.findUserByUsername(username);
    }

    /**
     * @return
     */
    @Override
    public List<User> getUsers() {
        log.info("getting all users");
        return userRepository.findAll();
    }

    /**
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findUserByUsername(username);

        log.info("User: ", user);

        if(Objects.isNull(user))
            throw new UsernameNotFoundException("Not Found");

        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();

        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });

        return new org.springframework.security.core.userdetails.User(user.getUsername(), user.getPassword(), authorities);
    }
}
