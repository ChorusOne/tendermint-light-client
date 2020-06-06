pub fn try_cast(val: u64) -> Option<i64> {
    if val > std::i64::MAX as u64 {
        None
    } else {
        Some(val as i64)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::try_cast;

    #[test]
    fn test_checked_cast() {
        let result = try_cast(1);
        assert!(result.is_some());
        let casted = result.unwrap();
        assert_eq!(casted, 1);

        let result = try_cast(std::i64::MAX as u64);
        assert!(result.is_some());
        let casted = result.unwrap();
        assert_eq!(casted, std::i64::MAX);

        let result = try_cast(std::i64::MAX as u64 + 1);
        assert!(result.is_none());
    }
}
