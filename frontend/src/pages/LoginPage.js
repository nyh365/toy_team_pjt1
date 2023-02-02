/* eslint-disable max-lines-per-function */
/* eslint-disable spaced-comment */
/**
 * 로그인 페이지
 * 로그인 상세기능 구현은 /api/Users.js 참고
 */

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { useForm } from 'react-hook-form';
import { setRefreshToken } from '../storage/Cookies';
import { Link } from 'react-router-dom';

import { loginUser } from '../api/Users';
import { SET_TOKEN } from '../store/Auth';

import KakaoButton from '../components/buttons/KakaoButton';
import NaverButton from '../components/buttons/NaverButton';
import GoogleButton from '../components/buttons/GoogleButton';
import Logo from '../components/PageLogo';
import '../styles/LoginPage.css';

const LoginPage = () => {
  //React Hooks
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const {
    register,
    setValue,
    handleSubmit,
    formState: { isSubmitting, errors },
  } = useForm();

  //onSubmit 요청에 동작할 코드
  //Backend로 유저정보를 전달
  const onValid = async ({ userEmail, userPassword }) => {
    //response 객체
    //참고: /api/Users.js
    const response = await loginUser({ userEmail, userPassword });

    //요청 응답이 오면 응답상태를 체크
    //response.status가 true면 응답이 200번대(성공)
    if (response.status) {
      console.log(response);
      //Cookie에 Refresh Token 저장
      setRefreshToken(response.json.refresh_token);
      //store에 Access Token 저장하도록 Action Dispatch
      //참고: /store/Auth.js
      dispatch(SET_TOKEN(response.json.access_token));

      //화면 이동(메인)
      return navigate('/');
    } else {
      console.log(response.json);
      window.alert(response.json.error);
    }

    //input폼 비워주는 코드
    setValue('userPassword', '');
  };

  const onSignUp = () => {
    navigate('/user/signup');
  };

  return (
    <div className="login">
      <Logo />
      <form className="loginform" onSubmit={handleSubmit(onValid)}>
        <div className="inputform">
          <div className="inputs">
            <input
              id="userEmail"
              type="email"
              placeholder="이메일을 입력하세요"
              {...register('userEmail', {
                required: '이메일은 필수 입력사항입니다.',
                pattern: {
                  value: /\S+@\S+\.\S+/, //정규식
                  message: '이메일이 형식에 맞지 않습니다.',
                },
              })}
            />
            {errors.email && <small role="alert">{errors.email.message}</small>}
            <input
              id="userPassword"
              type="password"
              placeholder="비밀번호를 입력하세요"
              {...register('userPassword', {
                minLength: {
                  value: 8,
                  message: '8자리 이상 비밀번호를 사용해주세요.',
                },
              })}
            />
            {errors.password && <small role="alert">{errors.password.message}</small>}
          </div>

          <button className="loginButton" type="submit" disabled={isSubmitting}>
            로그인
          </button>
        </div>

        <button className="signUpButton" onClick={onSignUp}>
          회원가입
        </button>
        <Link to="FindPassword" style={{ color: 'blue', textDecoration: 'none' }}>
          <small>비밀번호를 잊으셨나요?</small>
        </Link>
        <div className="socialLogin">
          <NaverButton />
          <KakaoButton />
          <GoogleButton />
        </div>
      </form>
    </div>
  );
};

export default LoginPage;
