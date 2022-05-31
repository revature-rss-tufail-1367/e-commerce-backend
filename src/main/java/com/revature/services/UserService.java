package com.revature.services;

import com.revature.models.User;

import java.util.Optional;

public interface UserService {
    Optional<User> findByCredentials(String email, String password);

    Optional<User> findByEmail(String email);

    Optional<User> findById(int id);

    User save(User user);

    /**
     * A method to send an email for password resets
     * @param email the email that the password reset confirmation will be sent to
     */
    void sendEmail(String email, int id);
}
