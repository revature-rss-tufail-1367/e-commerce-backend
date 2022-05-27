package com.revature.services;

import com.revature.models.User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class AuthServiceImpl implements AuthService{

    private final UserService userService;

    public AuthServiceImpl(UserService userService){
        this.userService = userService;
    }

    public Optional<User> findByCredentials(String email, String password){
        Optional<User> optionalUser = userService.findByEmail(email);
        if (!optionalUser.isPresent()) return optionalUser;

        User existingUser = optionalUser.get();
        if (User.encryptPassword(password, existingUser.getSaltBytes()).equals(existingUser.getPassword()))
            return optionalUser;

        return Optional.empty();
    }

    public User register(User user){
        user.encryptAndSetPassword();
        return userService.save(user);
    }

    @Override
    //TODO replace userId with UUID if allowed
    public void forgotPassword(String email){

        //TODO POST to reset request table {uuid,timestamp,userId}, if we end up being allowed to implement it
        userService.sendEmail(email);

    }

    @Override
    public Optional<User> findByUserId(Integer id){
        return userService.findById(id);
    }

    @Override
    public Optional<User> findByEmail(String email){
        return userService.findByEmail(email);
    }
}
