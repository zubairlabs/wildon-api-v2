use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use qrcode::{render::svg, QrCode};
use rand::RngCore;
use sha1::Sha1;

const TOTP_PERIOD_SECONDS: i64 = 30;
const TOTP_DIGITS: u32 = 6;
const BACKUP_CODE_LENGTH: usize = 8;
const BACKUP_CODE_CHARS: &[u8] = b"BCDFGHJKMPQRTVWXY2346789";

pub fn generate_authenticator_secret_base32() -> String {
    let mut secret = [0_u8; 20];
    rand::thread_rng().fill_bytes(&mut secret);
    BASE32_NOPAD.encode(&secret)
}

pub fn build_otpauth_uri(secret_base32: &str, issuer: &str, account_name: &str) -> String {
    let encoded_issuer = urlencoding::encode(issuer);
    let encoded_account = urlencoding::encode(account_name);
    format!(
        "otpauth://totp/{encoded_issuer}:{encoded_account}?secret={secret_base32}&issuer={encoded_issuer}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD_SECONDS}"
    )
}

pub fn build_otpauth_qr_svg_data_uri(otpauth_uri: &str) -> Option<String> {
    let code = QrCode::new(otpauth_uri.as_bytes()).ok()?;
    let svg = code
        .render::<svg::Color>()
        .min_dimensions(220, 220)
        .quiet_zone(true)
        .build();
    let encoded = BASE64_STANDARD.encode(svg.as_bytes());
    Some(format!("data:image/svg+xml;base64,{encoded}"))
}

pub fn verify_authenticator_totp(
    secret_base32: &str,
    otp_code: &str,
    drift_steps: i64,
    now_unix_seconds: i64,
) -> bool {
    let code = otp_code.trim();
    if code.len() != TOTP_DIGITS as usize || !code.chars().all(|ch| ch.is_ascii_digit()) {
        return false;
    }

    let Ok(secret) = BASE32_NOPAD.decode(secret_base32.trim().as_bytes()) else {
        return false;
    };
    let counter = now_unix_seconds.div_euclid(TOTP_PERIOD_SECONDS);
    let skew = drift_steps.clamp(0, 3);

    for offset in -skew..=skew {
        let Some(candidate_counter) = counter.checked_add(offset) else {
            continue;
        };
        if candidate_counter < 0 {
            continue;
        }
        let candidate = hotp(&secret, candidate_counter as u64, TOTP_DIGITS);
        let candidate_code = format!("{candidate:0width$}", width = TOTP_DIGITS as usize);
        if candidate_code == code {
            return true;
        }
    }

    false
}

pub fn generate_backup_codes(count: usize) -> Vec<String> {
    let target = count.clamp(1, 64);
    let mut codes = Vec::with_capacity(target);
    let mut bytes = [0_u8; BACKUP_CODE_LENGTH];
    let mut rng = rand::thread_rng();
    while codes.len() < target {
        rng.fill_bytes(&mut bytes);
        let mut raw = String::with_capacity(BACKUP_CODE_LENGTH);
        for byte in bytes {
            let idx = (byte as usize) % BACKUP_CODE_CHARS.len();
            raw.push(BACKUP_CODE_CHARS[idx] as char);
        }
        let formatted = format!("{}-{}", &raw[0..4], &raw[4..8]);
        if !codes.iter().any(|existing| existing == &formatted) {
            codes.push(formatted);
        }
    }
    codes
}

pub fn normalize_backup_code(code: &str) -> Option<String> {
    let normalized: String = code
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_uppercase())
        .collect();
    if normalized.len() != BACKUP_CODE_LENGTH {
        return None;
    }
    if normalized.chars().all(|ch| {
        BACKUP_CODE_CHARS
            .iter()
            .any(|allowed| *allowed as char == ch)
    }) {
        Some(normalized)
    } else {
        None
    }
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> u32 {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret).expect("invalid HMAC key");
    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();
    let offset = (result[19] & 0x0f) as usize;
    let binary = ((u32::from(result[offset] & 0x7f)) << 24)
        | ((u32::from(result[offset + 1])) << 16)
        | ((u32::from(result[offset + 2])) << 8)
        | u32::from(result[offset + 3]);
    binary % 10_u32.pow(digits)
}

#[cfg(test)]
mod tests {
    use super::{
        build_otpauth_qr_svg_data_uri, generate_backup_codes, normalize_backup_code,
        verify_authenticator_totp,
    };

    #[test]
    fn verifies_known_rfc_totp_vector() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert!(verify_authenticator_totp(secret, "287082", 0, 59));
    }

    #[test]
    fn rejects_invalid_code() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert!(!verify_authenticator_totp(secret, "000000", 0, 59));
    }

    #[test]
    fn backup_codes_generate_expected_shape() {
        let codes = generate_backup_codes(10);
        assert_eq!(codes.len(), 10);
        assert!(codes.iter().all(|value| {
            value.len() == 9
                && value.as_bytes()[4] == b'-'
                && normalize_backup_code(value).is_some()
        }));
    }

    #[test]
    fn backup_code_normalization_works() {
        let normalized = normalize_backup_code("bcdf-ghjk");
        assert_eq!(normalized.as_deref(), Some("BCDFGHJK"));
        assert!(normalize_backup_code("invalid-123").is_none());
    }

    #[test]
    fn qr_data_uri_generation_works() {
        let uri = "otpauth://totp/Wildon:test@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Wildon";
        let data_uri = build_otpauth_qr_svg_data_uri(uri).expect("qr");
        assert!(data_uri.starts_with("data:image/svg+xml;base64,"));
    }
}
