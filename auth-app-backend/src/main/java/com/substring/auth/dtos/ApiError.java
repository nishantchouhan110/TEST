package com.substring.auth.dtos;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

public record ApiError(
        int status,
        String error,
        String message,
        String path,
        OffsetDateTime  timestamp
) {
    public static ApiError of(int status, String error, String message, String path, Boolean o){
        return new ApiError(status,error,message,path,OffsetDateTime.now(ZoneOffset.UTC));
    }
    public static ApiError withoutTimeStamp(int status, String error, String message, String path,boolean notDateTime ){
        return new ApiError(status,error,message,path, null);

    }
}
