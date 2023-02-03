import React from 'react';
import { Link } from 'react-router-dom';

const GoogleButton = () => {
  return (
    <Link to="http://i8a804.p.ssafy.io:8040/oauth2/authorize/google?redirect_uri=http://localhost:3000/oauth/callback/google">
      <button type="button">
        <span>구글 로그인</span>
      </button>
    </Link>
  );
};

export default GoogleButton;