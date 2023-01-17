package com.softserve.itacademy.security;

import com.softserve.itacademy.model.User;
import com.softserve.itacademy.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service("securityService")
public class SecurityService implements UserDetailsService {
    private static final Logger logger = LoggerFactory.getLogger(SecurityService.class);

    private final UserRepository userRepository;

    @Autowired
    public SecurityService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("We are loadUserByUsername()");
        User user = userRepository.findByEmail(username);
        if(user==null) {
            logger.error("user==null");
            throw new UsernameNotFoundException("User with this email does not exists");
        }
        logger.info("Everything fine");
        return new Security(user);
    }
}
