/// AST for address formula expressions.
#[derive(Debug, Clone, PartialEq)]
pub enum Expr {
    /// Integer constant.
    Constant(i64),
    /// A module name to look up (e.g. `"game.exe"` or `<game.exe>`).
    Module(String),
    /// Addition.
    Add(Box<Expr>, Box<Expr>),
    /// Subtraction.
    Sub(Box<Expr>, Box<Expr>),
    /// Multiplication.
    Mul(Box<Expr>, Box<Expr>),
    /// Integer division.
    Div(Box<Expr>, Box<Expr>),
    /// Modulo.
    Rem(Box<Expr>, Box<Expr>),
    /// Unary negation.
    Negate(Box<Expr>),
    /// Dereference as a pointer-sized read: `[expr]`.
    Deref(Box<Expr>),
}
