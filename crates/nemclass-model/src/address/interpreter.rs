use crate::address::ast::Expr;
use crate::error::{ModelError, Result};

/// Trait for resolving module names to their base addresses.
pub trait ModuleResolver {
    fn resolve_module(&self, name: &str) -> Option<usize>;
}

/// Trait for reading a pointer-sized value from a target address.
pub trait MemoryReader {
    fn read_usize(&self, addr: usize) -> Result<usize>;
}

/// Evaluate an expression AST to a concrete address.
pub fn evaluate(
    expr: &Expr,
    modules: &dyn ModuleResolver,
    reader: &dyn MemoryReader,
) -> Result<usize> {
    match expr {
        Expr::Constant(n) => Ok(*n as usize),
        Expr::Module(name) => {
            modules.resolve_module(name)
                .ok_or_else(|| ModelError::ResolveError(format!("module not found: '{name}'")))
        }
        Expr::Add(lhs, rhs) => {
            Ok(evaluate(lhs, modules, reader)?.wrapping_add(evaluate(rhs, modules, reader)?))
        }
        Expr::Sub(lhs, rhs) => {
            Ok(evaluate(lhs, modules, reader)?.wrapping_sub(evaluate(rhs, modules, reader)?))
        }
        Expr::Mul(lhs, rhs) => {
            Ok(evaluate(lhs, modules, reader)?.wrapping_mul(evaluate(rhs, modules, reader)?))
        }
        Expr::Div(lhs, rhs) => {
            let divisor = evaluate(rhs, modules, reader)?;
            if divisor == 0 {
                return Err(ModelError::ResolveError("division by zero".to_string()));
            }
            Ok(evaluate(lhs, modules, reader)? / divisor)
        }
        Expr::Rem(lhs, rhs) => {
            let divisor = evaluate(rhs, modules, reader)?;
            if divisor == 0 {
                return Err(ModelError::ResolveError("modulo by zero".to_string()));
            }
            Ok(evaluate(lhs, modules, reader)? % divisor)
        }
        Expr::Negate(inner) => {
            // `wrapping_neg` (two's complement) to match the other ops and avoid a
            // debug-build panic on i64::MIN; negating an address is unusual but
            // formula resolution must never crash on it.
            Ok(evaluate(inner, modules, reader)?.wrapping_neg())
        }
        Expr::Deref(inner) => {
            let addr = evaluate(inner, modules, reader)?;
            reader.read_usize(addr)
        }
    }
}

// ---------------------------------------------------------------------------
// Blanket impl for module slices
// ---------------------------------------------------------------------------

impl ModuleResolver for &[nemclass_core::ModuleInfoWithName] {
    fn resolve_module(&self, name: &str) -> Option<usize> {
        self.iter()
            .find(|m| m.name.eq_ignore_ascii_case(name))
            .map(|m| m.base)
    }
}

impl ModuleResolver for Vec<nemclass_core::ModuleInfoWithName> {
    fn resolve_module(&self, name: &str) -> Option<usize> {
        self.as_slice().resolve_module(name)
    }
}
