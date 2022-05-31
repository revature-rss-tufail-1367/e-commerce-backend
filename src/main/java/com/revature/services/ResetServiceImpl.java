package com.revature.services;

import com.revature.models.ResetRequest;
import com.revature.models.User;
import com.revature.repositories.ResetRequestRepository;
import com.revature.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.persistence.EntityNotFoundException;
import java.util.Optional;

@Service
public class ResetServiceImpl implements ResetService {

    @Autowired
    private ResetRequestRepository resetRequestRepository;
    @Autowired
    private UserRepository userRepository;

    @Override
    public ResetRequest findById(int id) {
        Optional<ResetRequest> rp = resetRequestRepository.findById(id);
        return rp.orElse(null);
    }

    public ResetRequest createEntry(int userId){
        ResetRequest rr = new ResetRequest();
        rr.setTimeStamp(System.currentTimeMillis());
        rr.setUserId(userId);
        return resetRequestRepository.save(rr);
    }

    @Override
    public boolean compareTimestamp(long timeStamp) {
        long day = 86400000;
        return System.currentTimeMillis() - timeStamp < day;
    }

    @Override
    public User reset(String password, ResetRequest resetRequest){
        Optional<User> optionalUser = userRepository.findById(resetRequest.getUserId());
        System.out.println(resetRequest.toString());
        if (optionalUser.isPresent()){
            User foundUser = optionalUser.get();
            foundUser.setPassword(password);
            foundUser.encryptAndSetPassword();
            return userRepository.save(foundUser);
        }
        throw new EntityNotFoundException();
    }
}

