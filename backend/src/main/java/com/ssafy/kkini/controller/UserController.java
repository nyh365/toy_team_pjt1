package com.ssafy.kkini.controller;

import com.ssafy.kkini.dto.UserPasswordUpdateDto;
import com.ssafy.kkini.entity.AuthCode;
import com.ssafy.kkini.entity.PasswordCode;
import com.ssafy.kkini.entity.User;
import com.ssafy.kkini.service.AuthCodeService;
import com.ssafy.kkini.service.EmailService;
import com.ssafy.kkini.service.PasswordCodeService;
import com.ssafy.kkini.service.UserService;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/user")
@CrossOrigin(origins = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.PATCH, RequestMethod.DELETE})
public class UserController {
    private UserService userService;
    private AuthCodeService authCodeService;
    private PasswordCodeService passwordCodeService;
    private EmailService emailService;

    public UserController(UserService userService, AuthCodeService authCodeService, EmailService emailService, PasswordCodeService passwordCodeService) {
        this.userService = userService;
        this.authCodeService = authCodeService;
        this.passwordCodeService = passwordCodeService;
        this.emailService = emailService;
    }

    @ApiOperation(value = "이메일 인증코드 발송", notes = "입력한 이메일이 기존회원이 아니라면 이메일 인증코드 발송" )
    @GetMapping("/email/check")
    public ResponseEntity<Map<String, Object>> sendEmailCheck(@ApiParam(value = "회원가입에서 입력한 이메일" )@RequestParam String authCodeUserEmail) {
        emailService.sendEmailAuthCode(authCodeUserEmail);
        Map<String, Object> map = new HashMap<>();

        map.put("message", "success");
        return new ResponseEntity<Map<String, Object>>(map, HttpStatus.ACCEPTED);
    }

    @ApiOperation(value = "입력한 이메일 인증코드 일치확인", notes = "발급된 이메일 인증코드와 입력한 이메일 인증코드 일치 여부와 인증코드 만료여부 확인")
    @PostMapping("/email/check")
    public ResponseEntity<Map<String, Object>> emailCheck(@ApiParam(value = "입력한 인증코드")@RequestParam String authCodeContent,
                                                          @ApiParam(value = "회원가입에서 입력한 이메일") @RequestParam String authCodeUserEmail) {
        Map<String, Object> map = new HashMap<>();
        AuthCode authCode = authCodeService.getCodeByCodeContent(authCodeContent);

        //인증코드에 담긴 이메일과 입력한 이메일 비교
        if(authCodeUserEmail.equals(authCode.getAuthCodeUserEmail())
        && !(authCodeService.checkExpireAuthCode(authCode))) {
            map.put("message", "success");
            authCodeService.useAuthCode(authCode);  //인증코드 사용처리
            return new ResponseEntity<Map<String, Object>>(map, HttpStatus.ACCEPTED);
        } else {
            map.put("message", "fail");
            return new ResponseEntity<Map<String, Object>>(map, HttpStatus.BAD_REQUEST);
        }
    }

    @ApiOperation(value = "비밀번호 찾기(변경 URL 이메일로 전송)", notes = "입력한 이메일, 이름과 일치하는 유저확인 -> 있으면 비밀번호 변경 URL 이메일로 전송")
    @GetMapping ("/{userEmail}/password")
    public ResponseEntity<Map<String, Object>> findPassword(@ApiParam(value = "입력한 이메일") @PathVariable String userEmail,
                                                            @ApiParam(value = "입력한 이름") @RequestParam String userName) {
        Map<String, Object> map = new HashMap<>();
        //이메일과 이름 일치확인
        boolean flag = passwordCodeService.checkEmailAndName(userEmail, userName);
        //비밀번호코드 발급
        if(flag) {
            PasswordCode passwordCode = passwordCodeService.createPasswordCode(userEmail);  //비밀번호 코드 생성
            if(passwordCode != null) {
                emailService.sendEmailPasswordCode(userEmail, passwordCode.getPasswordCodeContent());  //이메일로 전송
                map.put("message", "success");
                return new ResponseEntity<Map<String, Object>>(map, HttpStatus.ACCEPTED);
            }
        }
        map.put("message", "fail");
        return new ResponseEntity<Map<String, Object>>(map, HttpStatus.BAD_REQUEST);
    }

    @ApiOperation(value = "비밀번호 변경 URL 유효검사", notes = "비밀번호 변경 URL 유효한지 검사")
    @GetMapping("/password")
    public ResponseEntity<Map<String, Object>> updatePassword(@ApiParam(value = "유저 이메일")@RequestParam String userEmail,
                                                              @ApiParam(value = "비밀번호 코드값")@RequestParam String passwordCodeContent) {
        Map<String, Object> map = new HashMap<>();

        //비밀번호 코드 가져오기
        PasswordCode originalPasswordCode = passwordCodeService.getCodeByUserEmail(userEmail);
        if(passwordCodeContent.equals(originalPasswordCode.getPasswordCodeContent())) {  //입력된 코드가 가장최근 코드와 같지 않으면 검사 필요없이 실패
            boolean expireYn = passwordCodeService.checkExpirePasswordCode(originalPasswordCode);
            if(!expireYn) {  //비밀번호 코드 유효 검사
                map.put("message", "success");
                return new ResponseEntity<Map<String, Object>>(map, HttpStatus.BAD_REQUEST);
            }
        }
        map.put("message", "fail");
        return new ResponseEntity<Map<String, Object>>(map, HttpStatus.BAD_REQUEST);
    }

    @ApiOperation(value = "비밀번호 변경 URL에서 비밀번호 변경", notes = "비밀번호 변경 URL에서 비밀번호 변경 처리, 비밀번호 코드 사용처리")
    @PatchMapping("/password")
    public ResponseEntity<Map<String, Object>> updatePassword(@ApiParam(value = "유저 이메일, 비밀번호 코드값, 입력한 새 비밀번호, 비밀번호 확인")
                                                                  @RequestBody UserPasswordUpdateDto userPasswordUpdateDto) {
        Map<String, Object> map = new HashMap<>();

        String userEmail = userPasswordUpdateDto.getUserEmail();
        String passwordCodeContent = userPasswordUpdateDto.getPasswordCodeContent();
        String newPassword = userPasswordUpdateDto.getUserPassword();
        String newPasswordCheck = userPasswordUpdateDto.getUserPasswordCheck();

        //비밀번호 코드 가져오기
        PasswordCode originalPasswordCode = passwordCodeService.getCodeByUserEmail(userEmail);
        if(!passwordCodeContent.equals(originalPasswordCode.getPasswordCodeContent())) {  //입력된 코드가 가장최근 코드와 같지 않으면 검사 필요없이 실패
            map.put("message", "fail");
            return new ResponseEntity<Map<String, Object>>(map, HttpStatus.BAD_REQUEST);
        }
        //마지막으로 비밀번호 코드 유효한지 검사, 유효 -> 입력한 새 비멀번호와 비밀번화 확인에 입력한 값 일치 확인
        boolean expireYn = passwordCodeService.checkExpirePasswordCode(originalPasswordCode);
        if(!expireYn && newPassword.equals(newPasswordCheck)) {
            //비밀번호 변경처리
            User updatedUser = userService.updatePasswordByEmail(userEmail, newPassword);
            if(updatedUser != null) {
                //비밀번호 코드 사용처리
                passwordCodeService.usePasswordCode(originalPasswordCode);
                map.put("message", "success");
                return new ResponseEntity<Map<String, Object>>(map, HttpStatus.ACCEPTED);
            }
        }

        map.put("message", "fail");
        return new ResponseEntity<Map<String, Object>>(map, HttpStatus.BAD_REQUEST);
    }

}
