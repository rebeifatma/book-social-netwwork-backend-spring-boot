package tn.fatouma.booksocialnetwork.security;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import tn.fatouma.booksocialnetwork.user.User;
import tn.fatouma.booksocialnetwork.user.UserRepository;
import org.springframework.security.core.userdetails.User.UserBuilder;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

//...

@Service
public class UserDetailsServiceImpl implements UserDetailsService {
    private final UserRepository userRepository;

    @Autowired
    public UserDetailsServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    private static final Logger logger = LoggerFactory.getLogger(UserDetailsServiceImpl.class);

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.info("Attempting to load user by username: {}", username);
        User user =  userRepository.findByEmail(username)
                .orElseThrow(() -> {
                    logger.error("User not found: {}", username);
                    return new UsernameNotFoundException("User not found");
                });

        UserBuilder userBuilder = org.springframework.security.core.userdetails.User.withUsername(user.getEmail());
        userBuilder.password(user.getPassword());
        userBuilder.authorities(user.getRoles().stream()
                .map(role -> role.getName())
                .toArray(String[]::new));

        return userBuilder.build();
    }
}
