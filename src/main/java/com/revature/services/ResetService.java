package com.revature.services;

import com.revature.models.ResetRequest;
import com.revature.models.User;

public interface ResetService {

    ResetRequest findById(int id);
    boolean compareTimestamp(long timeStamp);
    User reset(String password, ResetRequest resetRequest);
    ResetRequest createEntry(int userId);

}
