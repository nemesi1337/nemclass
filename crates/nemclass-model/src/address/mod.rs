pub mod ast;
pub mod interpreter;
pub mod parser;
pub mod tokenizer;

pub use ast::Expr;
pub use interpreter::{MemoryReader, ModuleResolver, evaluate};
pub use tokenizer::Tokenizer;

use crate::error::Result;

/// Parse an address formula string into an AST.
pub fn parse(input: &str) -> Result<Expr> {
    let tokens = Tokenizer::new(input).tokenize()?;
    let mut p = parser::Parser::new(tokens);
    let expr = p.parse_expr()?;
    p.finish()?;
    Ok(expr)
}

/// Parse and evaluate an address formula in one shot.
pub fn resolve_formula(
    formula: &str,
    modules: &dyn ModuleResolver,
    reader: &dyn MemoryReader,
) -> Result<usize> {
    let expr = parse(formula)?;
    evaluate(&expr, modules, reader)
}
