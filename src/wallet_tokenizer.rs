use std::io::{Buffer, IoResult, IoError, OtherIoError};

// There are only two tokens to worry about in Cykas' wallet file format: keys
// and values, both Strings.
#[deriving(PartialEq,Show)]
pub enum Token {
    KeyToken(String),
    ValueToken(String)
}

// Read the given Buffer and tokenize all of the input. Returns a vector of
// Tokens on success, or an IoError on failure.
pub fn tokenize<T: Buffer>(input: &mut T) -> IoResult<Vec<Token>> {
    let mut tokens: Vec<Token> = Vec::new();
    let mut current_token: Option<String> = None;
    let mut in_comment = false;
    let mut line_num = 1u;

    for ch in input.chars() {
        let ch = try!(ch);

        if ch == '\n' { line_num += 1; }
        if in_comment { in_comment = ch != '\n'; }
        if in_comment { continue; }

        if ch == '#' {
            in_comment = true;
            if current_token.is_some() {
                tokens.push(ValueToken(current_token.take_unwrap()));
            }
        } else if ch.is_whitespace() {
            if current_token.is_some() {
                tokens.push(ValueToken(current_token.take_unwrap()));
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
        } else {
            let error = IoError {
                kind: OtherIoError,
                desc: "unexpected input",
                detail: Some(format!("Unexpected char '{}' on line {}", ch, line_num))
            };
            return Err(error);
        }
    }

    if current_token.is_some() {
        tokens.push(ValueToken(current_token.take_unwrap()));
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use std::io::{MemReader, OtherIoError};

    use super::{KeyToken, ValueToken};
    use super::tokenize;

    #[test]
    fn test_tokenize() {
        let mut buf = MemReader::new(b" 0 a: 1 2 3\nb: 4\n5# #c: 6\nd:7".to_vec());
        let tokens = tokenize(&mut buf);
        assert!(tokens.is_ok());
        assert_eq!(tokens.unwrap(), vec![ValueToken("0".to_string()),
                                         KeyToken("a".to_string()),
                                         ValueToken("1".to_string()),
                                         ValueToken("2".to_string()),
                                         ValueToken("3".to_string()),
                                         KeyToken("b".to_string()),
                                         ValueToken("4".to_string()),
                                         ValueToken("5".to_string()),
                                         KeyToken("d".to_string()),
                                         ValueToken("7".to_string())]);
    }

    #[test]
    fn test_tokenize_nothing() {
        let mut buf = MemReader::new(vec![]);
        let tokens = tokenize(&mut buf);
        assert!(tokens.is_ok());
        assert_eq!(tokens.unwrap().len(), 0);
    }

    #[test]
    fn test_tokenize_unexpected_colon() {
        let mut buf = MemReader::new(b"a::1".to_vec());
        let tokens = tokenize(&mut buf);
        assert!(tokens.is_err());
        assert_eq!(tokens.unwrap_err().kind, OtherIoError);
    }
}

