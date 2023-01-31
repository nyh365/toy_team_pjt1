package com.ssafy.kkini.entity;
import com.ssafy.kkini.dto.AuthProvider;
import lombok.*;
import org.hibernate.annotations.ColumnDefault;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.DynamicInsert;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.sql.Timestamp;


@Getter
@Entity
@DynamicInsert
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "USER")
public class User {
    @Id // primary key
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(columnDefinition = "INT UNSIGNED")
    private Long userId;

    private String userName;

    private String userEmail;

    private String userPassword;

    private String userRole;

    private String userNickname;

    private int userBirthYear;

    private String userGender;

    @CreationTimestamp
    private Timestamp userActivation;

    @CreationTimestamp
    private Timestamp userJoinDate;

    @Enumerated(EnumType.STRING)
    private AuthProvider userProvider;
    private String userProviderId;

    @ColumnDefault("0")
    private int userReported;

    @Builder
    public User(String email, String name, String password,String nickname,String gender, int birthYear,AuthProvider provider,String providerId){
        this.userEmail = email;
        this.userName = name;
        this.userPassword = password;
        this.userNickname = nickname;
        this.userGender = gender;
        this.userRole = "ROLE_USER";
        this.userBirthYear = birthYear;
        this.userProvider = provider;
        this.userProviderId = providerId;
    }


    public void changeNickname(String nickname) {
        this.userNickname = nickname;
    }

    public void changePassword(String password){
        this.userPassword = password;
    }
}