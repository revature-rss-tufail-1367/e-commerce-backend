package com.revature.advice;

import com.revature.exceptions.ExpiredRequestException;
import com.revature.exceptions.NotLoggedInException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.servlet.http.HttpServletRequest;

@RestControllerAdvice
public class RestExceptionHandler {

    @ExceptionHandler(NotLoggedInException.class)
    public ResponseEntity<Object> handleNotLoggedInException(HttpServletRequest request, NotLoggedInException notLoggedInException) {

        String errorMessage = "Must be logged in to perform this action";

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorMessage);
    }

    @ExceptionHandler(ExpiredRequestException.class)
   public ResponseEntity<Object> handleExpiredRequestException(HttpServletRequest request, ExpiredRequestException exception) {

        String errorMessage = "The password reset request expired. Please try again. Links expire in 24 hours.";

        return ResponseEntity.status(HttpStatus.RESET_CONTENT).body(errorMessage);
   }
}
