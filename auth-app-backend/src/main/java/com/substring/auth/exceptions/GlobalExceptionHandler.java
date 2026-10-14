package com.substring.auth.exceptions;

import com.substring.auth.dtos.ApiError;
import com.substring.auth.dtos.ErrorResponce;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler({
         UsernameNotFoundException.class,
         BadCredentialsException.class,
         CredentialsExpiredException.class,
         DisabledException.class
    })
    public ResponseEntity<ApiError> handleAuthException(Exception e, HttpServletRequest request){
     logger.info("Exception: {}",e.getClass().getName());
      var apiError =  ApiError.of(HttpStatus.BAD_REQUEST.value(),"Bad Request,e",e.getMessage(),request.getRequestURI(), null);
        return ResponseEntity.badRequest().body(apiError);
    }
    // resource not found exception handler methad
    @ExceptionHandler(ResourceNotFoundException.class)
    public ResponseEntity<ErrorResponce> handleResourceNotFoundException(ResourceNotFoundException exception ){
      ErrorResponce internalServerError = new ErrorResponce(exception.getMessage(), HttpStatus.NOT_FOUND,404);
      return ResponseEntity.status(HttpStatus.NOT_FOUND).body(internalServerError);

    }

    @ExceptionHandler( IllegalArgumentException.class)
    public ResponseEntity<ErrorResponce> handleIllegalArgumentException(IllegalArgumentException exception ){
        ErrorResponce internalServerError = new ErrorResponce(exception.getMessage(), HttpStatus.BAD_REQUEST,400);
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(internalServerError);

    }



}
