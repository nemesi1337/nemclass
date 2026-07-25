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

/// Maximum nesting depth for the recursive-descent parser. A formula like
/// `----…----0` (unary chain) or `[[[[…]]]]0` (bracket/paren nesting) recurses
/// once per token; without a bound, a long crafted string — which can arrive
/// via a *shared* `project.nemclass` file or a script-declared class — would
/// overflow the native stack and abort the process. Real address formulas are
/// only a handful of levels deep, so this cap never rejects a legitimate input.
const MAX_DEPTH: usize = 128;

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
        self.parse_additive(0)
    }

    fn parse_additive(&mut self, depth: usize) -> Result<Expr> {
        let mut lhs = self.parse_multiplicative(depth)?;
        loop {
            match self.peek() {
                Some(Token::Plus) => {
                    self.pos += 1;
                    let rhs = self.parse_multiplicative(depth)?;
                    lhs = Expr::Add(Box::new(lhs), Box::new(rhs));
                }
                Some(Token::Minus) => {
                    self.pos += 1;
                    let rhs = self.parse_multiplicative(depth)?;
                    lhs = Expr::Sub(Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_multiplicative(&mut self, depth: usize) -> Result<Expr> {
        let mut lhs = self.parse_unary(depth)?;
        loop {
            match self.peek() {
                Some(Token::Star) => {
                    self.pos += 1;
                    let rhs = self.parse_unary(depth)?;
                    lhs = Expr::Mul(Box::new(lhs), Box::new(rhs));
                }
                Some(Token::Slash) => {
                    self.pos += 1;
                    let rhs = self.parse_unary(depth)?;
                    lhs = Expr::Div(Box::new(lhs), Box::new(rhs));
                }
                Some(Token::Percent) => {
                    self.pos += 1;
                    let rhs = self.parse_unary(depth)?;
                    lhs = Expr::Rem(Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self, depth: usize) -> Result<Expr> {
        // Guard the unary chain directly: a run of `-` recurses here once per
        // token without ever reaching `parse_primary`, so the depth check must
        // live here too, not only in `parse_primary`.
        if depth > MAX_DEPTH {
            return Err(ModelError::ParseError(
                "expression nested too deeply".to_string(),
            ));
        }
        if matches!(self.peek(), Some(Token::Minus)) {
            self.pos += 1;
            let inner = self.parse_unary(depth + 1)?;
            return Ok(Expr::Negate(Box::new(inner)));
        }
        self.parse_primary(depth)
    }

    fn parse_primary(&mut self, depth: usize) -> Result<Expr> {
        if depth > MAX_DEPTH {
            return Err(ModelError::ParseError(
                "expression nested too deeply".to_string(),
            ));
        }
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
                // Recurse through `parse_additive` (not the public `parse_expr`,
                // which would reset `depth` to 0 and defeat the nesting guard).
                let inner = self.parse_additive(depth + 1)?;
                self.expect(&Token::CloseParen)?;
                Ok(inner)
            }
            Some(Token::OpenBracket) => {
                self.pos += 1;
                let inner = self.parse_additive(depth + 1)?;
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

#[cfg(test)]
mod tests {
    use crate::address::parse;

    /// A pathologically deep bracket nest must fail gracefully with a
    /// `ParseError`, not overflow the stack and abort the process.
    #[test]
    fn deeply_nested_brackets_error_instead_of_overflowing() {
        let depth = super::MAX_DEPTH + 50;
        let formula = format!("{}0{}", "[".repeat(depth), "]".repeat(depth));
        let err = parse(&formula).expect_err("deep nesting should be rejected");
        assert!(
            err.to_string().contains("nested too deeply"),
            "unexpected error: {err}"
        );
    }

    /// A long unary-minus chain recurses through `parse_unary` once per token;
    /// it must be bounded the same way as bracket nesting.
    #[test]
    fn long_unary_chain_errors_instead_of_overflowing() {
        let formula = format!("{}0", "-".repeat(super::MAX_DEPTH + 50));
        let err = parse(&formula).expect_err("deep unary chain should be rejected");
        assert!(
            err.to_string().contains("nested too deeply"),
            "unexpected error: {err}"
        );
    }

    /// Formulas nested within the limit still parse — the guard must not reject
    /// legitimate (shallow) input.
    #[test]
    fn moderate_nesting_still_parses() {
        // Well under MAX_DEPTH: a handful of dereferences and parens.
        let formula = "[[[<game.exe>+0x10]+0x20]+0x30]";
        assert!(parse(formula).is_ok(), "moderate nesting should parse");
        assert!(parse("-(-(-(1)))").is_ok(), "shallow unary should parse");
    }
}
