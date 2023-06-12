use core::panic;

pub fn sum_byte_arr(arr: Vec<u8>) -> usize {
    let mut sum = 0;
    for i in arr.chunks(2) {
        let [a, b] = i else {
            panic!("Invalid byte array");
        };
        sum += ((*a as usize) << 8) | *b as usize;
    }
    sum
}

pub fn checksum(sum: usize) -> [u8; 2] {
    let checksum = (sum - ((sum >> 16) << 16) + (sum >> 16)) ^ 0xffff;
    (checksum as u16).to_be_bytes()
}

pub fn iptobyte(ip: &str) -> [u8; 4] {
    match ip
        .split('.')
        .map(|v| v.parse::<usize>().unwrap())
        .collect::<Vec<_>>()[..]
    {
        [a, b, c, d] => [a as u8, b as u8, c as u8, d as u8],
        _ => panic!("Invalid IP address: {}", ip),
    }
}

#[cfg(test)]
mod tests {
    use super::checksum;

    #[test]
    fn test_checksum() {
        assert_eq!(checksum(0x1f7dd), [8, 33]);
    }
}
