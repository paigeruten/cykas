//! Simple parser for a very simple key-values file format used by Cykas
//! wallets.

use std::io::{Buffer, IoResult, IoError, OtherIoError};

// There are only two tokens to worry about in Cykas' wallet file format: keys
// and values, both Strings.
#[deriving(PartialEq,Show)]
enum Token {
    KeyToken(String),
    ValueToken(String)
}

/// Tokenizes the given Buffer and parses that into a Vec that maps String keys
/// to vectors of Strings. Returns an IoError on failure.
pub fn parse<T: Buffer>(input: &mut T) -> IoResult<Vec<(String, Vec<String>)>> {
    let tokens = try!(tokenize(input));
    let mut tokens_iter = tokens.into_iter();
    let mut result: Vec<(String, Vec<String>)> = Vec::new();

    for token in tokens_iter {
        match token {
            KeyToken(key) => {
                if result.iter().any(|&(ref alias, _)| *alias == key) {
                    return Err(IoError {
                        kind: OtherIoError,
                        desc: "unexpected key",
                        detail: Some(format!("Key '{}' used more than once in wallet file", key))
                    });
                }

                result.push((key, Vec::new()));
            }
            ValueToken(val) => {
                if result.is_empty() {
                    return Err(IoError {
                        kind: OtherIoError,
                        desc: "unexpected value",
                        detail: Some(format!("Wallet file starts with a value instead of a key"))
                    });
                }

                let index_last = result.len() - 1;
                let &(_, ref mut values) = result.get_mut(index_last);
                values.push(val);
            }
        }
    }

    Ok(result)
}

// Read the given Buffer and tokenize all of the input. Returns a vector of
// Tokens on success, or an IoError on failure.
fn tokenize<T: Buffer>(input: &mut T) -> IoResult<Vec<Token>> {
    let mut tokens: Vec<Token> = Vec::new();
    let mut current_token: Option<String> = None;
    let mut in_comment = false;
    let mut line_num = 1u;

    for ch in input.chars() {
        let ch = try!(ch);

        if ch == '\n' {
            line_num += 1;
            if in_comment { in_comment = false; }
        }

        if in_comment { continue; }

        if ch == '#' {
            in_comment = true;
            if current_token.is_some() {
                tokens.push(ValueToken(current_token.take().unwrap()));
            }
        } else if ch.is_whitespace() {
            if current_token.is_some() {
                tokens.push(ValueToken(current_token.take().unwrap()));
            }
        } else if ch.is_alphanumeric() || ch == '_' || ch == '!' {
            if current_token.is_some() {
                let mut token_string = current_token.take().unwrap();
                token_string.push(ch);
                current_token = Some(token_string);
            } else {
                current_token = Some(ch.to_string());
            }
        } else if ch == ':' && current_token.is_some() {
            tokens.push(KeyToken(current_token.take().unwrap()));
        } else {
            return Err(IoError {
                kind: OtherIoError,
                desc: "unexpected input",
                detail: Some(format!("Unexpected char '{}' on line {}", ch, line_num))
            });
        }
    }

    if current_token.is_some() {
        tokens.push(ValueToken(current_token.take().unwrap()));
    }

    Ok(tokens)
}

#[cfg(test)]
mod tests {
    use std::io::{MemReader, OtherIoError};

    use super::{KeyToken, ValueToken};
    use super::{parse, tokenize};

    #[test]
    fn test_parse() {
        let mut buf = MemReader::new(b" a: 1 2 !b: 3\n4# #c: 5\nd:6".to_vec());
        let result = parse(&mut buf);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec![("a".to_string(), vec!["1".to_string(), "2".to_string()]),
                                         ("!b".to_string(), vec!["3".to_string(), "4".to_string()]),
                                         ("d".to_string(), vec!["6".to_string()])]);
    }

    #[test]
    fn test_parse_nothing() {
        let mut buf = MemReader::new(vec![]);
        let result = parse(&mut buf);
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn test_parse_unexpected_value() {
        let mut buf = MemReader::new(b"abc def: hij".to_vec());
        let result = parse(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, OtherIoError);
    }

    #[test]
    fn test_parse_unexpected_key() {
        let mut buf = MemReader::new(b"a: 1 b: 2 a: 3".to_vec());
        let result = parse(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind, OtherIoError);
    }

    #[test]
    fn test_tokenize() {
        let mut buf = MemReader::new(b" 0 a: 1 2 3 !b: 4\n5# #c: 6\nd:7".to_vec());
        let tokens = tokenize(&mut buf);
        assert!(tokens.is_ok());
        assert_eq!(tokens.unwrap(), vec![ValueToken("0".to_string()),
                                         KeyToken("a".to_string()),
                                         ValueToken("1".to_string()),
                                         ValueToken("2".to_string()),
                                         ValueToken("3".to_string()),
                                         KeyToken("!b".to_string()),
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
        assert!(tokens.unwrap().is_empty());
    }

    #[test]
    fn test_tokenize_unexpected_colon() {
        let mut buf = MemReader::new(b"a::1".to_vec());
        let tokens = tokenize(&mut buf);
        assert!(tokens.is_err());
        assert_eq!(tokens.unwrap_err().kind, OtherIoError);
    }
}

