package com.ssafy.kkini.service;

import com.ssafy.kkini.dto.*;
import com.ssafy.kkini.entity.User;
import com.ssafy.kkini.repository.UserRepository;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.Optional;

@Service
public class UserService {
    private UserRepository userRepository;

    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public UserService(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Transactional
    public User createUser(UserCreateFormDto userCreateFormDto) {
        return userRepository.save(userCreateFormDto.toEntity());
    }

    @Transactional
    public User join(UserCreateFormDto userCreateFormDto){
        userCreateFormDto.setUserPassword(bCryptPasswordEncoder.encode(userCreateFormDto.getUserPassword()));
        User user = userCreateFormDto.toEntity();

        return userRepository.save(user);
    }

    public User login(UserLoginFormDto userLoginFormDto) {
        if (userLoginFormDto.getUserEmail() == null || userLoginFormDto.getUserPassword() == null) return null;
        Optional<User> user = userRepository.findByUserEmail(userLoginFormDto.getUserEmail());
        if(bCryptPasswordEncoder.matches(userLoginFormDto.getUserPassword(), user.get().getUserPassword())) return user.get();
        else return null;
    }

    @Transactional
    public int delete(int userid) {
        User user = userRepository.findByUserId(userid);
        if(user != null) {
            userRepository.delete(user);
            return 1;
        }
        return 0;
    }

    @Transactional
    public User nicknameModify(UserNicknameModifyFormDto userNicknameModifyFormDto) {
        User user = userRepository.findById(userNicknameModifyFormDto.getUserId()).get();
        if(user != null) {
            user.changeNickname(userNicknameModifyFormDto.getUserNickname());
            return userRepository.save(user);
        }else return null;
    }

    @Transactional
    public User passwordModify(UserPasswordModifyFormDto userPasswordModifyFormDto) {
        User user = userRepository.findByUserId(userPasswordModifyFormDto.getUserId());
        if(user != null) {
            user.changePassword(userPasswordModifyFormDto.getUserPassword());
            return userRepository.save(user);
        }else return null;
    }

    public User nicknameCheck(String userNickname) {
        return userRepository.findByUserNickname(userNickname);
    }

    @Transactional
    public User updatePasswordByEmail(String email, String newPassword) {
        User user = userRepository.findByUserEmail(email).get();
        UserInfoDto userInfoDto = new UserInfoDto(user);
        userInfoDto.setUserPassword(newPassword);

        return userRepository.save(userInfoDto.toEntity());
    }
}