pub fn try_cast_u64_to_i64(val: u64) -> Option<i64> {
    if val > std::i64::MAX as u64 {
        None
    } else {
        Some(val as i64)
    }
}

#[cfg(test)]
mod tests {
    use crate::utils::try_cast_u64_to_i64;

    #[test]
    fn test_try_cast_u64_to_i64() {
        let result = try_cast_u64_to_i64(1);
        assert!(result.is_some());
        let casted = result.unwrap();
        assert_eq!(casted, 1);

        let result = try_cast_u64_to_i64(std::i64::MAX as u64);
        assert!(result.is_some());
        let casted = result.unwrap();
        assert_eq!(casted, std::i64::MAX);

        let result = try_cast_u64_to_i64(std::i64::MAX as u64 + 1);
        assert!(result.is_none());
    }
}
