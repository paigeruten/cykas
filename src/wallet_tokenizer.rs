use std::io::{Buffer, IoResult};

pub enum Token {
    KeyToken(String),
    ValueToken(String)
}

pub fn tokenize<T: Buffer>(input: &mut T) -> IoResult<Vec<Token>> {
    let mut tokens: Vec<Token> = Vec::new();
    let mut current_token: Option<String> = None;
    let mut in_comment = false;

    for ch in input.chars() {
        let ch = try!(ch);
        if in_comment {
            in_comment = ch != '\n';
        } else if ch == '#' {
            in_comment = true;
            if current_token.is_some() {
                tokens.push(ValueToken(current_token.take_unwrap()));
                assert!(current_token.is_none());
            }
        } else if ch.is_whitespace() {
            if current_token.is_some() {
                tokens.push(ValueToken(current_token.take_unwrap()));
                assert!(current_token.is_none());
            }
        } else if ch.is_alphanumeric() || ch == '_' {
            if current_token.is_some() {
                let mut token_string = current_token.take_unwrap();
                token_string.push_char(ch);
                current_token = Some(token_string);
            } else {
                current_token = Some(ch.to_string());
            }
        } else if ch == ':' && current_token.is_some() {
            tokens.push(KeyToken(current_token.take_unwrap()));
            assert!(current_token.is_none());
        } else {
            fail!("unexpected input!");
        }
    }

    if current_token.is_some() {
        tokens.push(ValueToken(current_token.take_unwrap()));
        assert!(current_token.is_none());
    }

    Ok(tokens)
}

