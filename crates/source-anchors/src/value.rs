//! Invariant: the rendering of a `const` initializer holds only decimal
//! digits, the identifiers of path segments joined by `::`, the operators
//! `+ - * / << >>`, parentheses and single spaces. Space is its only
//! whitespace, every binary operation is parenthesized to state the
//! grouping the parser found, and an identifier directly before `(` is the
//! target type of a cast of the parenthesized operand.

use syn::{BinOp, Expr, Lit, PathArguments, Type};

/// A cast renders as its target type's name applied to its operand
/// (`u64(A)`), so the reader decides whether that type holds the operand's
/// value. A cast to a type that is no single identifier renders as nothing.
pub(crate) fn integer_arithmetic(expression: &Expr) -> Option<String> {
    match expression {
        Expr::Lit(literal) => match &literal.lit {
            Lit::Int(integer) => Some(integer.base10_digits().to_owned()),
            _ => None,
        },
        Expr::Path(path) if path.qself.is_none() => path
            .path
            .segments
            .iter()
            .map(|segment| {
                matches!(segment.arguments, PathArguments::None).then(|| segment.ident.to_string())
            })
            .collect::<Option<Vec<String>>>()
            .map(|names| names.join("::")),
        Expr::Paren(inner) => integer_arithmetic(&inner.expr),
        Expr::Group(inner) => integer_arithmetic(&inner.expr),
        Expr::Cast(cast) => {
            let Type::Path(target) = &*cast.ty else {
                return None;
            };
            let name = target.path.get_ident().filter(|_| target.qself.is_none())?;
            Some(format!("{name}({})", integer_arithmetic(&cast.expr)?))
        }
        Expr::Binary(binary) => {
            let operator = match binary.op {
                BinOp::Add(_) => "+",
                BinOp::Sub(_) => "-",
                BinOp::Mul(_) => "*",
                BinOp::Div(_) => "/",
                BinOp::Shl(_) => "<<",
                BinOp::Shr(_) => ">>",
                _ => return None,
            };
            let left = integer_arithmetic(&binary.left)?;
            let right = integer_arithmetic(&binary.right)?;
            Some(format!("({left} {operator} {right})"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::integer_arithmetic;

    fn rendered(source: &str) -> Option<String> {
        integer_arithmetic(&syn::parse_str(source).expect("the expression parses"))
    }

    #[test]
    fn literals_render_as_decimal_digits_and_operations_state_the_parsed_grouping() {
        for (source, rendering) in [
            ("4_096usize", "4096"),
            ("0x10", "16"),
            ("0b1010_u8", "10"),
            ("1 + 2 * 3", "(1 + (2 * 3))"),
            ("(1 + 2) * 3", "((1 + 2) * 3)"),
            ("1 << 10 >> 2", "((1 << 10) >> 2)"),
            ("8 - 2 - 1", "((8 - 2) - 1)"),
            ("64 / 4 / 2", "((64 / 4) / 2)"),
        ] {
            assert_eq!(rendered(source).as_deref(), Some(rendering), "{source}");
        }
    }

    #[test]
    fn a_cast_renders_as_its_target_applied_to_its_operand_and_binds_tighter_than_arithmetic() {
        assert_eq!(rendered("A as u64 + 2").as_deref(), Some("(u64(A) + 2)"));
        assert_eq!(rendered("A as u8 as u64").as_deref(), Some("u64(u8(A))"));
        assert_eq!(rendered("7 as f64").as_deref(), Some("f64(7)"));
        assert_eq!(
            rendered("((crate::storage::IO_UNIT - UNIT_OVERHEAD) / ENTRY_BYTES) as u64").as_deref(),
            Some("u64(((crate::storage::IO_UNIT - UNIT_OVERHEAD) / ENTRY_BYTES))")
        );
        assert_eq!(
            rendered("::core::primitive::usize::MAX").as_deref(),
            Some("core::primitive::usize::MAX")
        );
    }

    #[test]
    fn every_other_form_renders_as_nothing() {
        for source in [
            "\"4096\"",
            "4096.0",
            "'4'",
            "true",
            "-1",
            "!0",
            "7 % 2",
            "6 & 3",
            "1 == 1",
            "size_of::<u64>()",
            "4096 as crate::Word",
            "4096 as Wrapping<u64>",
            "4096 as *const u8",
            "Vec::<u8>::CAPACITY",
            "<u8 as Limit>::MAX",
            "[1, 2]",
            "{ 4096 }",
            "if SMALL { 1 } else { 2 }",
            "1 + \"\ttab\nline\".len()",
        ] {
            assert_eq!(rendered(source), None, "{source}");
        }
    }
}
