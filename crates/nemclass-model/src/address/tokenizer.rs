use crate::error::{ModelError, Result};

/// Tokens produced by the address-formula lexer.
#[derive(Debug, Clone, PartialEq)]
pub enum Token {
    /// An integer constant (decimal or `0x` hex).
    Number(i64),
    /// A module/identifier name from `<...>` or `"..."` syntax.
    Identifier(String),
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    OpenParen,
    CloseParen,
    OpenBracket,
    CloseBracket,
}

pub struct Tokenizer<'a> {
    src: &'a [u8],
    pos: usize,
}

impl<'a> Tokenizer<'a> {
    pub fn new(input: &'a str) -> Self {
        Self { src: input.as_bytes(), pos: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn skip_whitespace(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.pos += 1;
        }
    }

    fn read_number(&mut self) -> Result<Token> {
        let start = self.pos;
        // Check for 0x prefix
        let is_hex = self.src.get(self.pos) == Some(&b'0')
            && matches!(self.src.get(self.pos + 1), Some(b'x' | b'X'));

        if is_hex {
            self.pos += 2; // skip 0x
            let hex_start = self.pos;
            while matches!(self.peek(), Some(b'0'..=b'9' | b'a'..=b'f' | b'A'..=b'F')) {
                self.pos += 1;
            }
            let hex_str = std::str::from_utf8(&self.src[hex_start..self.pos]).unwrap();
            let value = i64::from_str_radix(hex_str, 16)
                .map_err(|_| ModelError::ParseError(format!("invalid hex number at pos {start}")))?;
            return Ok(Token::Number(value));
        }

        // Decimal (but may have hex digits — only if it starts with 0-9)
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.pos += 1;
        }
        let dec_str = std::str::from_utf8(&self.src[start..self.pos]).unwrap();
        let value = dec_str.parse::<i64>()
            .map_err(|_| ModelError::ParseError(format!("invalid decimal number at pos {start}")))?;
        Ok(Token::Number(value))
    }

    /// Read `<...>` identifier.
    fn read_angle_identifier(&mut self) -> Result<Token> {
        self.pos += 1; // skip '<'
        let start = self.pos;
        while self.peek().is_some() && self.peek() != Some(b'>') {
            self.pos += 1;
        }
        if self.peek() != Some(b'>') {
            return Err(ModelError::ParseError("unclosed '<' in identifier".to_string()));
        }
        let name = std::str::from_utf8(&self.src[start..self.pos]).unwrap().to_string();
        self.pos += 1; // skip '>'
        Ok(Token::Identifier(name))
    }

    /// Read `"..."` quoted module name.
    fn read_quoted_identifier(&mut self) -> Result<Token> {
        self.pos += 1; // skip '"'
        let start = self.pos;
        while self.peek().is_some() && self.peek() != Some(b'"') {
            self.pos += 1;
        }
        if self.peek() != Some(b'"') {
            return Err(ModelError::ParseError("unclosed '\"' in identifier".to_string()));
        }
        let name = std::str::from_utf8(&self.src[start..self.pos]).unwrap().to_string();
        self.pos += 1; // skip '"'
        Ok(Token::Identifier(name))
    }

    pub fn tokenize(mut self) -> Result<Vec<Token>> {
        let mut tokens = Vec::new();
        loop {
            self.skip_whitespace();
            let Some(ch) = self.peek() else { break };
            let tok = match ch {
                b'+' => { self.pos += 1; Token::Plus }
                b'-' => { self.pos += 1; Token::Minus }
                b'*' => { self.pos += 1; Token::Star }
                b'/' => { self.pos += 1; Token::Slash }
                b'%' => { self.pos += 1; Token::Percent }
                b'(' => { self.pos += 1; Token::OpenParen }
                b')' => { self.pos += 1; Token::CloseParen }
                b'[' => { self.pos += 1; Token::OpenBracket }
                b']' => { self.pos += 1; Token::CloseBracket }
                b'<' => self.read_angle_identifier()?,
                b'"' => self.read_quoted_identifier()?,
                b'0'..=b'9' => self.read_number()?,
                _ => {
                    return Err(ModelError::ParseError(
                        format!("unexpected character '{}'", ch as char)
                    ));
                }
            };
            tokens.push(tok);
        }
        Ok(tokens)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_hex_and_ops() {
        let toks = Tokenizer::new("0x1000 + 0x20").tokenize().unwrap();
        assert_eq!(toks, vec![Token::Number(0x1000), Token::Plus, Token::Number(0x20)]);
    }

    #[test]
    fn tokenize_angle_ident() {
        let toks = Tokenizer::new("<game.exe>+0x10").tokenize().unwrap();
        assert_eq!(toks, vec![
            Token::Identifier("game.exe".to_string()),
            Token::Plus,
            Token::Number(0x10),
        ]);
    }

    #[test]
    fn tokenize_quoted_ident() {
        let toks = Tokenizer::new("\"game.exe\"+0x10").tokenize().unwrap();
        assert_eq!(toks, vec![
            Token::Identifier("game.exe".to_string()),
            Token::Plus,
            Token::Number(0x10),
        ]);
    }

    #[test]
    fn tokenize_deref() {
        let toks = Tokenizer::new("[0x1000]+0x8").tokenize().unwrap();
        assert_eq!(toks, vec![
            Token::OpenBracket,
            Token::Number(0x1000),
            Token::CloseBracket,
            Token::Plus,
            Token::Number(0x8),
        ]);
    }
}
