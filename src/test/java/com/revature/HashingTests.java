package com.revature;

import com.revature.controllers.AuthController;
import com.revature.dtos.LoginRequest;
import com.revature.dtos.RegisterRequest;
import com.revature.models.User;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpSession;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;

@SpringBootTest
public class HashingTests{

    @Autowired
    AuthController authController;

    static String getDefaultSalt(){
        return HexFormat.of().formatHex("NotSoRandomSalt?".getBytes());
    }

    /**
     * Salt Maker is implemented in models.User.getSalt() method
     * takes roughly 6 seconds for Jalil's computer for 1 million tests
     */
    @Test
    public void HashTest(){
        for (int j = 0; j < 1_000; j++) {
            byte[] salt = SaltMaker();
            String parsed = HexFormat.of().formatHex(salt);
            byte[] unSalt = HexFormat.of().parseHex(parsed);
            Assertions.assertTrue(Arrays.equals(salt, unSalt));
        }
    }

    // takes 1 minute 20 secs on Jalil's computer for 1k tests using PBKDF2WithHmacSHA1
    // takes 2 minute 20 secs on Jalil's computer for 1k tests using PBKDF2WithHmacSHA256
    @Test
    public void UserHashTest(){
        User testUser = new User(1, "testuser@gmail.com", "password", "test", "user", getDefaultSalt());
        for (int j = 0; j < 10; j++) {
            testUser.encryptAndSetPassword("password");
            Assertions.assertNotEquals("password", testUser.getPassword());
            Assertions.assertEquals(User.encryptPassword("password", testUser.getSaltBytes()), testUser.getPassword());
        }
    }

    @Test
    void TestPassword(){
        User testUser = new User(1, "testuser@gmail.com", "password", "test", "user", getDefaultSalt());
        testUser.encryptAndSetPassword(testUser.getPassword());
        System.out.println(testUser.getPassword());
    }

    @Test
    public void RegisterSuccessTest(){
        RegisterRequest request = new RegisterRequest();
        request.setFirstName("test");
        request.setLastName("user");
        request.setEmail("newuser@gmail.com");
        request.setPassword("password");
        ResponseEntity<User> test = authController.register(request);
        Assertions.assertTrue(test.getStatusCodeValue() >= 200 && test.getStatusCodeValue() < 300);
    }

    @Test
    public void failedRegisterTest(){
        RegisterRequest request = new RegisterRequest();
        request.setFirstName("test");
        request.setLastName("user");
        request.setEmail("testuser@gmail.com");//existing email
        request.setPassword("password");
        ResponseEntity<User> test = authController.register(request);
        Assertions.assertFalse(test.getStatusCodeValue() >= 200 && test.getStatusCodeValue() < 300);
    }

    @Test
    public void LoginTest(){
        LoginRequest request = new LoginRequest();
        request.setEmail("testuser@gmail.com");
        request.setPassword("password");
        ResponseEntity<User> test = authController.login(request, new MockHttpSession());
        //Assertions.assertTrue(test.getStatusCodeValue() >= 200 && test.getStatusCodeValue() < 300);
    }

    @Test
    public void failedLoginTest(){
        LoginRequest request = new LoginRequest();
        request.setEmail("testuser@gmail.com");
        request.setPassword("badPassword");
        ResponseEntity<User> test = authController.login(request, new MockHttpSession());
        Assertions.assertFalse(test.getStatusCodeValue() >= 200 && test.getStatusCodeValue() < 300);
    }

    //Salt Maker is implemented in models.User.getSalt() method
    private byte[] SaltMaker(){
        byte[] randBytes = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(randBytes);
        return randBytes;
    }
}
