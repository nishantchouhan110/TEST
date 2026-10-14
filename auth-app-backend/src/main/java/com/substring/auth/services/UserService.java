package com.substring.auth.services;

import com.substring.auth.dtos.UserDto;

public interface UserService {

    //crate user
     UserDto createUser(UserDto userDto);

    // get user by email
    UserDto getUserByEmail(String email);

    // update user
    UserDto updateUser(UserDto userDto, String userId);

    // delete user
    void deleteUser(String userId);

    //get user by id
    UserDto getUserById(String userId);

    //get all users
    Iterable<UserDto> getAllUsers();


}
