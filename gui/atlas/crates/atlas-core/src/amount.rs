use crate::{Error, Result};
use serde_json::{Number, Value};
use std::str::FromStr;
pub const COIN: i64 = 100_000_000;
pub const MAX_MONEY: i64 = 21_000_000 * COIN;
/// Consensus money, in atoms. Never create a monetary value from f64.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Amount(i64);
impl Amount {
    pub fn from_atoms(n: i64) -> Result<Self> {
        if !(0..=MAX_MONEY).contains(&n) {
            return Err(Error::new(
                "MONEY_RANGE",
                "Amount outside the node's money range",
            ));
        }
        Ok(Self(n))
    }
    pub fn atoms(self) -> i64 {
        self.0
    }
    pub fn parse(s: &str) -> Result<Self> {
        if s.is_empty()
            || s.len() > 32
            || s.starts_with('+')
            || s.starts_with('-')
            || s.contains(['e', 'E'])
        {
            return Err(Error::new(
                "AMOUNT",
                "Use a nonnegative decimal, at most eight places",
            ));
        }
        let mut pieces = s.split('.');
        let whole = pieces.next().unwrap_or("");
        let fraction = pieces.next().unwrap_or("");
        if pieces.next().is_some()
            || whole.is_empty()
            || (whole.len() > 1 && whole.starts_with('0'))
            || !whole.bytes().all(|b| b.is_ascii_digit())
            || fraction.len() > 8
            || !fraction.bytes().all(|b| b.is_ascii_digit())
            || (s.contains('.') && fraction.is_empty())
        {
            return Err(Error::new("AMOUNT", "Malformed decimal amount"));
        }
        let w = whole
            .parse::<i64>()
            .map_err(|_| Error::new("AMOUNT", "Amount overflow"))?;
        let f = if fraction.is_empty() {
            0
        } else {
            format!("{fraction:0<8}")
                .parse::<i64>()
                .map_err(|_| Error::new("AMOUNT", "Invalid fraction"))?
        };
        Self::from_atoms(
            w.checked_mul(COIN)
                .and_then(|v| v.checked_add(f))
                .ok_or_else(|| Error::new("AMOUNT", "Amount overflow"))?,
        )
    }
    pub fn decimal(self) -> String {
        format!("{}.{:08}", self.0 / COIN, self.0 % COIN)
    }
    pub fn json(self) -> Result<Value> {
        Ok(Value::Number(Number::from_str(&self.decimal()).map_err(
            |_| Error::new("AMOUNT", "Cannot serialize exact amount"),
        )?))
    }
    pub fn from_value(v: &Value) -> Result<Self> {
        match v {
            Value::String(s) => Self::parse(s),
            Value::Number(n) => Self::parse(&n.to_string()),
            _ => Err(Error::new(
                "AMOUNT",
                "Amount is neither decimal text nor JSON number",
            )),
        }
    }
    pub fn checked_add(self, other: Self) -> Result<Self> {
        Self::from_atoms(
            self.0
                .checked_add(other.0)
                .ok_or_else(|| Error::new("AMOUNT", "Amount overflow"))?,
        )
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exact() {
        assert_eq!(Amount::parse("0.00000001").unwrap().atoms(), 1);
        assert_eq!(Amount::parse("21000000").unwrap().atoms(), MAX_MONEY);
        assert_eq!(Amount::parse("0.10000001").unwrap().decimal(), "0.10000001");
    }
    #[test]
    fn reject() {
        for s in [
            "",
            "-1",
            "+1",
            "1e-8",
            "NaN",
            "01",
            "1.",
            ".1",
            "1.000000001",
            "21000000.00000001",
            "9223372036854775807",
        ] {
            assert!(Amount::parse(s).is_err(), "{s}");
        }
    }
    #[test]
    fn roundtrip() {
        for n in [0, 1, 42, 99999999, 100000000, MAX_MONEY] {
            let a = Amount::from_atoms(n).unwrap();
            assert_eq!(Amount::parse(&a.decimal()).unwrap(), a);
        }
    }
}
