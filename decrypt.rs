// $t@$h
// QVLx Labs
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::Path;
use std::thread;

/* Cargo.toml
[dependencies]
hex = "0.4"
*/

// TODO: Automate the initial binwalk -E to check if encrypted in the first place

fn main() -> io::Result<()> {
    let filename = "firmware.bin";
    let data = read_file(filename)?;
    let firmware_name = Path::new(filename).file_stem().unwrap().to_str().unwrap();

    for pattern_length in [4, 8, 16].iter() {
        let patterns = find_common_patterns(&data, *pattern_length);
        let mut sorted_patterns: Vec<_> = patterns.iter().collect();
        sorted_patterns.sort_by(|a, b| b.1.cmp(a.1));

        for (pattern, _) in sorted_patterns.iter().take(10) {
            let data_clone = data.clone();
            let firmware_clone = firmware_name.to_string();
            let pattern_clone = pattern.clone();

            thread::spawn(move || {
                let decrypted_data = xor_decrypt(&data_clone, &pattern_clone);
                let filename = format!("{}_xord_{}.bin", firmware_clone, hex::encode(&pattern_clone));
                write_to_file(&decrypted_data, filename).unwrap();
            });

            for shift in 1..=3 {
                let caesar_decrypted = caesar_decrypt(&data_clone, shift);
                write_to_file(&caesar_decrypted, format!("{}_caesar_shift_{}_{}.bin", firmware_clone, shift, hex::encode(&pattern_clone)))?;
            }

            if *pattern_length == 8 {
                let reversed_data = reverse(&data_clone);
                write_to_file(&reversed_data, format!("{}_reversed_{}.bin", firmware_clone, hex::encode(&pattern_clone)))?;

                let bitwise_not_data = bitwise_not(&data_clone);
                write_to_file(&bitwise_not_data, format!("{}_bitwise_not_{}.bin", firmware_clone, hex::encode(&pattern_clone)))?;
            }
        }
    }

    Ok(())
}

fn read_file(filename: &str) -> io::Result<Vec<u8>> {
    let mut file = fs::File::open(filename)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    Ok(buffer)
}

fn find_common_patterns(data: &[u8], pattern_length: usize) -> HashMap<Vec<u8>, usize> {
    let mut pattern_counts = HashMap::new();
    for window in data.windows(pattern_length) {
        *pattern_counts.entry(window.to_vec()).or_insert(0) += 1;
    }
    pattern_counts
}

fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .zip(key.iter().cycle())
        .map(|(&byte, &key_byte)| byte ^ key_byte)
        .collect()
}

fn write_to_file(data: &[u8], filename: String) -> io::Result<()> {
    let mut file = File::create(filename)?;
    file.write_all(data)?;
    Ok(())
}

fn caesar_decrypt(data: &[u8], shift: u8) -> Vec<u8> {
    data.iter().map(|&b| b.wrapping_add(shift)).collect()
}

fn reverse(data: &[u8]) -> Vec<u8> {
    let mut rev = data.to_vec();
    rev.reverse();
    rev
}

fn bitwise_not(data: &[u8]) -> Vec<u8> {
    data.iter().map(|&b| !b).collect()
}

// TODO: Will need to add logic to automatically invoke binwalk -E and check if still encrypted
