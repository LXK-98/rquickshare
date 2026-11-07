use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};

use anyhow::anyhow;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use get_if_addrs::get_if_addrs;
use hkdf::Hkdf;
use num_bigint::{BigUint, ToBigInt};
use p256::elliptic_curve::rand_core::OsRng;
use p256::{PublicKey, SecretKey};
use rand::{Rng, RngCore};
use sha2::Sha256;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

use crate::CUSTOM_DOWNLOAD;

#[derive(Debug, Clone, PartialEq)]
#[allow(dead_code)]
pub enum DeviceType {
    Unknown = 0,
    Phone = 1,
    Tablet = 2,
    Laptop = 3,
}

#[allow(dead_code)]
impl DeviceType {
    pub fn from_raw_value(value: u8) -> Self {
        match value {
            0 => DeviceType::Unknown,
            1 => DeviceType::Phone,
            2 => DeviceType::Tablet,
            3 => DeviceType::Laptop,
            _ => DeviceType::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RemoteDeviceInfo {
    pub name: String,
    pub device_type: DeviceType,
}

impl RemoteDeviceInfo {
    pub fn serialize(&self) -> Vec<u8> {
        // 1 byte: Version(3 bits)|Visibility(1 bit)|Device Type(3 bits)|Reserved(1 bit)
        let mut endpoint_info: Vec<u8> = vec![((self.device_type.clone() as u8) << 1) & 0b111];

        // 16 bytes: unknown random bytes
        endpoint_info.extend((0..16).map(|_| rand::rng().random_range(0..=255)));

        // Device name in UTF-8 prefixed with 1-byte length
        let mut name_chars = self.name.as_bytes().to_vec();
        if name_chars.len() > 255 {
            name_chars.truncate(255);
        }
        endpoint_info.push(name_chars.len() as u8);
        endpoint_info.extend(name_chars);

        endpoint_info
    }
}

pub fn gen_mdns_name(endpoint_id: [u8; 4]) -> String {
    let mut name_b = Vec::new();

    let pcp: [u8; 1] = [0x23];
    name_b.extend_from_slice(&pcp);

    name_b.extend_from_slice(&endpoint_id);

    let service_id: [u8; 3] = [0xFC, 0x9F, 0x5E];
    name_b.extend_from_slice(&service_id);

    let unknown_bytes: [u8; 2] = [0x00, 0x00];
    name_b.extend_from_slice(&unknown_bytes);

    URL_SAFE_NO_PAD.encode(&name_b)
}

pub fn gen_mdns_endpoint_info(device_type: u8, device_name: &str) -> String {
    let mut record = Vec::new();

    // 1 byte: Version(3 bits)|Visibility(1 bit)|Device Type(3 bits)|Reserved(1 bits)
    // Device types: unknown=0, phone=1, tablet=2, laptop=3
    record.push(device_type << 1);

    let unknown_bytes = rand::rng().random::<[u8; 16]>();
    record.extend_from_slice(&unknown_bytes);

    let device_name = device_name.as_bytes();
    let length = device_name.len() as u8;
    record.push(length);
    record.extend_from_slice(device_name);

    URL_SAFE_NO_PAD.encode(&record)
}

pub fn parse_mdns_endpoint_info(encoded_str: &str) -> Result<(DeviceType, String), anyhow::Error> {
    let decoded_bytes = URL_SAFE_NO_PAD.decode(encoded_str)?;
    if decoded_bytes.len() < 19 {
        return Err(anyhow!("Invalid data length"));
    }

    let device_type = (decoded_bytes[0] >> 1) & 0x7;
    let name_length = decoded_bytes[17] as usize;
    if 18 + name_length > decoded_bytes.len() {
        return Err(anyhow!("Invalid name length"));
    }

    let device_name_bytes = &decoded_bytes[18..18 + name_length];
    let device_name = String::from_utf8(device_name_bytes.to_vec())?;

    Ok((DeviceType::from_raw_value(device_type), device_name))
}

pub async fn stream_read_exact(
    socket: &mut TcpStream,
    buf: &mut [u8],
) -> Result<(), anyhow::Error> {
    match socket.read_exact(buf).await {
        Ok(_) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

pub fn gen_ecdsa_keypair() -> (SecretKey, PublicKey) {
    let secret_key = SecretKey::random(&mut OsRng);
    let public_key = secret_key.public_key();

    (secret_key, public_key)
}

pub fn encode_point(unsigned: Bytes) -> Result<Vec<u8>, anyhow::Error> {
    let big_int = BigUint::from_bytes_be(&unsigned)
        .to_bigint()
        .ok_or_else(|| anyhow!("Failed to convert to bigint"))?;

    Ok(big_int.to_signed_bytes_be())
}

/// Normalises one P-256 affine coordinate to the fixed 32 bytes that SEC1 wants.
///
/// `EcP256PublicKey` carries x and y as big-endian **two's complement** integers
/// (securemessage.proto says so explicitly), so their length varies with the
/// value: a leading 0x00 is prepended when the top bit is set, giving 33 bytes,
/// and leading zero bytes are stripped otherwise, giving 31 or fewer. Both are
/// valid on the wire.
///
/// An uncompressed SEC1 point is fixed-width — `0x04 || x[32] || y[32]` — so a
/// short coordinate has to be left-padded, not appended raw. Appending raw
/// yields a 63- or 64-byte buffer and `EncodedPoint::from_bytes` fails with
/// "elliptic curve point encoding error". A P-256 coordinate encodes short
/// roughly once in 512, so this bites about 1 connection in 262.
pub fn p256_coordinate(coordinate: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 32];

    // Over-long input carries a sign byte (or more); keep the low 32 bytes.
    let significant = if coordinate.len() > 32 {
        &coordinate[coordinate.len() - 32..]
    } else {
        coordinate
    };

    // Right-align, so missing leading bytes stay zero.
    padded[32 - significant.len()..].copy_from_slice(significant);
    padded
}

#[cfg(test)]
mod coordinate_tests {
    use super::*;

    #[test]
    fn pads_a_short_coordinate_on_the_left() {
        // 31 bytes, as produced when the value is below 2^247.
        let short = [0xAAu8; 31];
        let padded = p256_coordinate(&short);

        assert_eq!(padded.len(), 32);
        assert_eq!(padded[0], 0x00, "the pad must go on the left");
        assert_eq!(&padded[1..], &short[..]);
    }

    #[test]
    fn strips_a_two_s_complement_sign_byte() {
        // 33 bytes: a 0x00 prepended because the top bit of the value is set.
        let mut signed = vec![0x00u8];
        signed.extend_from_slice(&[0xFFu8; 32]);

        assert_eq!(p256_coordinate(&signed), [0xFFu8; 32]);
    }

    #[test]
    fn leaves_an_exact_coordinate_alone() {
        let exact = [0x42u8; 32];
        assert_eq!(p256_coordinate(&exact), exact);
    }

    #[test]
    fn an_empty_coordinate_is_all_zeroes() {
        // Not a valid key, but it must not panic on the slice arithmetic.
        assert_eq!(p256_coordinate(&[]), [0u8; 32]);
    }

    #[test]
    fn every_length_yields_a_usable_sec1_point() {
        // The property that actually matters: whatever arrives on the wire, the
        // rebuilt buffer is always 65 bytes.
        for len in 0..=40usize {
            let coordinate = vec![0x5Au8; len];
            let mut point = vec![0x04];
            point.extend_from_slice(&p256_coordinate(&coordinate));
            point.extend_from_slice(&p256_coordinate(&coordinate));
            assert_eq!(
                point.len(),
                65,
                "length {len} produced {} bytes",
                point.len()
            );
        }
    }
}

pub fn hkdf_extract_expand(
    salt: &[u8],
    input: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, anyhow::Error> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), input);
    let mut okm = vec![0u8; output_len];
    hkdf.expand(info, &mut okm)
        .map_err(|e| anyhow!("HKDF expand failed: {}", e))?;
    Ok(okm)
}

pub fn to_four_digit_string(bytes: &Vec<u8>) -> String {
    let k_hash_modulo = 9973;
    let k_hash_base_multiplier = 31;

    let mut hash = 0;
    let mut multiplier = 1;
    for &byte in bytes {
        let byte = byte as i8 as i32;
        hash = (hash + byte * multiplier) % k_hash_modulo;
        multiplier = (multiplier * k_hash_base_multiplier) % k_hash_modulo;
    }

    format!("{:04}", hash.abs())
}

pub fn gen_random(size: usize) -> Vec<u8> {
    let mut data = vec![0; size];
    rand::rng().fill_bytes(&mut data);

    data
}

pub fn get_download_dir() -> PathBuf {
    let cdown = CUSTOM_DOWNLOAD.read();
    match cdown {
        Ok(mg) => {
            if mg.is_some() {
                return mg.as_ref().unwrap().to_path_buf();
            }
        }
        Err(_) => {
            // TODO
        }
    }

    if let Some(user_dirs) = directories::UserDirs::new() {
        if let Some(dd) = user_dirs.download_dir() {
            return dd.to_path_buf();
        }

        return user_dirs.home_dir().to_path_buf();
    }

    Path::new("/").to_path_buf()
}

pub fn is_not_self_ip(ip_address: &Ipv4Addr) -> bool {
    if let Ok(if_addrs) = get_if_addrs() {
        for if_addr in if_addrs {
            if if_addr.ip() == *ip_address {
                return false;
            }
        }
    }

    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gen_and_parse_mdns_info() {
        let device_name = "a_device_name";
        let device_type = DeviceType::Laptop;

        dbg!(&device_type);
        dbg!(device_type.clone() as u8);

        let info = gen_mdns_endpoint_info(device_type.clone() as u8, device_name);
        let parse_info = parse_mdns_endpoint_info(&info).unwrap();

        assert_eq!(parse_info.1, device_name);
        assert_eq!(parse_info.0, device_type);
    }
}
