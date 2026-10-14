package com.substring.auth.dtos;

import org.springframework.http.HttpStatus;

public record ErrorResponce(
        String message,
        HttpStatus status,
        int statusCode

) {
}
