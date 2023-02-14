import React, { Component } from 'react';
import styled from 'styled-components';

const Username = styled.p`
  color: #42387a;
  font-size: 0.8rem;
  font-weight: 600;
  padding: 5px 0 10px 0;
`;

const MessageContainer = styled.div`
  width: 20vw;

  background: #d6ebfc;
`;

const ChatText = styled.p`
  font-size: 1rem;
`;

class Message extends Component {
  render() {
    const { text, userName } = this.props;

    return (
      <MessageContainer>
        <Username>{userName}</Username>
        <ChatText>{text}</ChatText>
      </MessageContainer>
    );
  }
}

export default Message;
