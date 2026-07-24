/// Recursive-descent parser: tokens → Expr AST.
///
/// Precedence (lowest to highest):
///   additive:       + -
///   multiplicative: * / %
///   unary:          -
///   primary:        number, identifier, (expr), [expr]
use crate::address::ast::Expr;
use crate::address::tokenizer::Token;
use crate::error::{ModelError, Result};

pub struct Parser {
    tokens: Vec<Token>,
    pos: usize,
}

impl Parser {
    pub fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<&Token> {
        let tok = self.tokens.get(self.pos)?;
        self.pos += 1;
        Some(tok)
    }

    fn expect(&mut self, expected: &Token) -> Result<()> {
        match self.peek() {
            Some(t) if t == expected => {
                self.pos += 1;
                Ok(())
            }
            Some(t) => Err(ModelError::ParseError(format!(
                "expected {expected:?}, got {t:?}"
            ))),
            None => Err(ModelError::ParseError(format!(
                "expected {expected:?}, got end of input"
            ))),
        }
    }

    pub fn parse_expr(&mut self) -> Result<Expr> {
        self.parse_additive()
    }

    fn parse_additive(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_multiplicative()?;
        loop {
            match self.peek() {
                Some(Token::Plus) => {
                    self.pos += 1;
                    let rhs = self.parse_multiplicative()?;
                    lhs = Expr::Add(Box::new(lhs), Box::new(rhs));
                }
                Some(Token::Minus) => {
                    self.pos += 1;
                    let rhs = self.parse_multiplicative()?;
                    lhs = Expr::Sub(Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_multiplicative(&mut self) -> Result<Expr> {
        let mut lhs = self.parse_unary()?;
        loop {
            match self.peek() {
                Some(Token::Star) => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    lhs = Expr::Mul(Box::new(lhs), Box::new(rhs));
                }
                Some(Token::Slash) => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    lhs = Expr::Div(Box::new(lhs), Box::new(rhs));
                }
                Some(Token::Percent) => {
                    self.pos += 1;
                    let rhs = self.parse_unary()?;
                    lhs = Expr::Rem(Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Expr> {
        if matches!(self.peek(), Some(Token::Minus)) {
            self.pos += 1;
            let inner = self.parse_unary()?;
            return Ok(Expr::Negate(Box::new(inner)));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<Expr> {
        match self.peek() {
            Some(Token::Number(_)) => {
                if let Some(Token::Number(n)) = self.advance() {
                    Ok(Expr::Constant(*n))
                } else {
                    unreachable!()
                }
            }
            Some(Token::Identifier(_)) => {
                if let Some(Token::Identifier(s)) = self.advance() {
                    Ok(Expr::Module(s.clone()))
                } else {
                    unreachable!()
                }
            }
            Some(Token::OpenParen) => {
                self.pos += 1;
                let inner = self.parse_expr()?;
                self.expect(&Token::CloseParen)?;
                Ok(inner)
            }
            Some(Token::OpenBracket) => {
                self.pos += 1;
                let inner = self.parse_expr()?;
                self.expect(&Token::CloseBracket)?;
                Ok(Expr::Deref(Box::new(inner)))
            }
            Some(tok) => Err(ModelError::ParseError(format!("unexpected token: {tok:?}"))),
            None => Err(ModelError::ParseError("unexpected end of input".to_string())),
        }
    }

    pub fn finish(self) -> Result<()> {
        if self.pos < self.tokens.len() {
            Err(ModelError::ParseError(format!(
                "trailing tokens starting at index {}: {:?}",
                self.pos, self.tokens[self.pos]
            )))
        } else {
            Ok(())
        }
    }
}
