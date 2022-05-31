package com.revature.services;

import com.revature.exceptions.ExpiredRequestException;
import com.revature.models.User;
import java.util.Optional;

public interface AuthService {
    Optional<User> findByCredentials(String email, String password);


    User register(User user);

    /**
     * A method that will determine if the user is registered and then email the account on file.
     * @param email the email to search for in the user table of the database
     * @return true - if the email was found in the database (not intended to be passed to front end)
     */
    void forgotPassword(String email);

    Optional<User> findByUserId(Integer id);
    User resetPassword(String password,int resetId) throws ExpiredRequestException;

    Optional<User> findByEmail(String email);
}
