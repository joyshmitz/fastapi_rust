//! HTTP Digest authentication (RFC 7616 / RFC 2617).
//!
//! Scope (bd-gl3v):
//! - Parse `Authorization: Digest ...`
//! - Provide response computation + verification helpers
//! - Keep dependencies minimal (no external crypto crates)

use crate::password::constant_time_eq;
use crate::Method;
use core::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Md5,
    Md5Sess,
    Sha256,
    Sha256Sess,
}

impl DigestAlgorithm {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "MD5" | "md5" => Some(Self::Md5),
            "MD5-sess" | "md5-sess" => Some(Self::Md5Sess),
            "SHA-256" | "sha-256" => Some(Self::Sha256),
            "SHA-256-sess" | "sha-256-sess" => Some(Self::Sha256Sess),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_sess(self) -> bool {
        matches!(self, Self::Md5Sess | Self::Sha256Sess)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestQop {
    Auth,
    AuthInt,
}

impl DigestQop {
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "auth" => Some(Self::Auth),
            "auth-int" => Some(Self::AuthInt),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auth => "auth",
            Self::AuthInt => "auth-int",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestAuth {
    pub username: String,
    pub realm: Option<String>,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub opaque: Option<String>,
    pub algorithm: DigestAlgorithm,
    pub qop: Option<DigestQop>,
    pub nc: Option<String>,
    pub cnonce: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DigestAuthError {
    pub kind: DigestAuthErrorKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestAuthErrorKind {
    MissingHeader,
    InvalidUtf8,
    InvalidScheme,
    InvalidFormat(&'static str),
    MissingField(&'static str),
    UnsupportedQop,
    UnsupportedAlgorithm,
    InvalidNc,
    InvalidResponseHex,
}

impl fmt::Display for DigestAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            DigestAuthErrorKind::MissingHeader => write!(f, "Missing Authorization header"),
            DigestAuthErrorKind::InvalidUtf8 => write!(f, "Invalid Authorization header encoding"),
            DigestAuthErrorKind::InvalidScheme => {
                write!(f, "Authorization header must use Digest scheme")
            }
            DigestAuthErrorKind::InvalidFormat(m) => write!(f, "Invalid Digest header: {m}"),
            DigestAuthErrorKind::MissingField(k) => write!(f, "Digest header missing field: {k}"),
            DigestAuthErrorKind::UnsupportedQop => write!(f, "Unsupported Digest qop"),
            DigestAuthErrorKind::UnsupportedAlgorithm => write!(f, "Unsupported Digest algorithm"),
            DigestAuthErrorKind::InvalidNc => write!(f, "Invalid Digest nc value"),
            DigestAuthErrorKind::InvalidResponseHex => write!(f, "Invalid Digest response value"),
        }
    }
}

impl std::error::Error for DigestAuthError {}

impl DigestAuth {
    /// Parse an `Authorization` header value of the form `Digest ...`.
    pub fn parse(header_value: &str) -> Result<Self, DigestAuthError> {
        let mut it = header_value.splitn(2, char::is_whitespace);
        let scheme = it.next().unwrap_or("");
        if !scheme.eq_ignore_ascii_case("digest") {
            return Err(DigestAuthError {
                kind: DigestAuthErrorKind::InvalidScheme,
            });
        }
        let rest = it.next().unwrap_or("").trim();
        if rest.is_empty() {
            return Err(DigestAuthError {
                kind: DigestAuthErrorKind::InvalidFormat("missing parameters"),
            });
        }

        let params = parse_kv_list(rest).map_err(|m| DigestAuthError {
            kind: DigestAuthErrorKind::InvalidFormat(m),
        })?;

        let username = params
            .get("username")
            .ok_or(DigestAuthError {
                kind: DigestAuthErrorKind::MissingField("username"),
            })?
            .to_string();

        let nonce = params
            .get("nonce")
            .ok_or(DigestAuthError {
                kind: DigestAuthErrorKind::MissingField("nonce"),
            })?
            .to_string();

        let uri = params
            .get("uri")
            .ok_or(DigestAuthError {
                kind: DigestAuthErrorKind::MissingField("uri"),
            })?
            .to_string();

        let response = params
            .get("response")
            .ok_or(DigestAuthError {
                kind: DigestAuthErrorKind::MissingField("response"),
            })?
            .to_string();

        if !is_lower_hex(&response) {
            return Err(DigestAuthError {
                kind: DigestAuthErrorKind::InvalidResponseHex,
            });
        }

        let realm = params.get("realm").map(ToString::to_string);
        let opaque = params.get("opaque").map(ToString::to_string);

        let algorithm = match params.get("algorithm") {
            Some(v) => DigestAlgorithm::parse(v).ok_or(DigestAuthError {
                kind: DigestAuthErrorKind::UnsupportedAlgorithm,
            })?,
            None => DigestAlgorithm::Md5,
        };

        let qop = match params.get("qop") {
            Some(v) => Some(DigestQop::parse(v).ok_or(DigestAuthError {
                kind: DigestAuthErrorKind::UnsupportedQop,
            })?),
            None => None,
        };

        let nc = params.get("nc").map(ToString::to_string);
        if let Some(nc) = &nc {
            if nc.len() != 8 || !nc.as_bytes().iter().all(|b| b.is_ascii_hexdigit()) {
                return Err(DigestAuthError {
                    kind: DigestAuthErrorKind::InvalidNc,
                });
            }
        }

        let cnonce = params.get("cnonce").map(ToString::to_string);

        Ok(Self {
            username,
            realm,
            nonce,
            uri,
            response,
            opaque,
            algorithm,
            qop,
            nc,
            cnonce,
        })
    }

    /// Compute the expected `response=` value for this challenge (lower hex).
    ///
    /// Supports:
    /// - algorithms: MD5, MD5-sess, SHA-256, SHA-256-sess
    /// - qop: auth (auth-int is rejected)
    pub fn compute_expected_response(
        &self,
        method: Method,
        realm: &str,
        password: &str,
    ) -> Result<String, DigestAuthError> {
        let qop = match self.qop {
            Some(DigestQop::Auth) => Some("auth"),
            Some(DigestQop::AuthInt) => {
                return Err(DigestAuthError {
                    kind: DigestAuthErrorKind::UnsupportedQop,
                });
            }
            None => None,
        };

        let ha1_0 = hash_hex(
            self.algorithm,
            format_args!("{}:{}:{}", self.username, realm, password),
        );
        let ha1 = if self.algorithm.is_sess() {
            let Some(cnonce) = self.cnonce.as_deref() else {
                return Err(DigestAuthError {
                    kind: DigestAuthErrorKind::MissingField("cnonce"),
                });
            };
            hash_hex(
                self.algorithm,
                format_args!("{}:{}:{}", ha1_0, self.nonce, cnonce),
            )
        } else {
            ha1_0
        };

        let ha2 = hash_hex(
            self.algorithm,
            format_args!("{}:{}", method.as_str(), self.uri),
        );

        let response = if let Some(qop) = qop {
            let Some(nc) = self.nc.as_deref() else {
                return Err(DigestAuthError {
                    kind: DigestAuthErrorKind::MissingField("nc"),
                });
            };
            let Some(cnonce) = self.cnonce.as_deref() else {
                return Err(DigestAuthError {
                    kind: DigestAuthErrorKind::MissingField("cnonce"),
                });
            };
            hash_hex(
                self.algorithm,
                format_args!("{}:{}:{}:{}:{}:{}", ha1, self.nonce, nc, cnonce, qop, ha2),
            )
        } else {
            // RFC 2069 compatibility (no qop).
            hash_hex(
                self.algorithm,
                format_args!("{}:{}:{}", ha1, self.nonce, ha2),
            )
        };

        Ok(response)
    }

    /// Verify `response=` against the expected value (timing-safe).
    pub fn verify(
        &self,
        method: Method,
        realm: &str,
        password: &str,
    ) -> Result<bool, DigestAuthError> {
        let expected = self.compute_expected_response(method, realm, password)?;
        Ok(constant_time_eq(
            expected.as_bytes(),
            self.response.as_bytes(),
        ))
    }
}

fn is_lower_hex(s: &str) -> bool {
    !s.is_empty()
        && s.as_bytes()
            .iter()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn parse_kv_list(input: &str) -> Result<std::collections::HashMap<String, String>, &'static str> {
    let mut out = std::collections::HashMap::new();
    let bytes = input.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        // Skip whitespace + commas.
        while i < bytes.len() && (bytes[i].is_ascii_whitespace() || bytes[i] == b',') {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }

        // Key token.
        let key_start = i;
        while i < bytes.len()
            && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-' || bytes[i] == b'_')
        {
            i += 1;
        }
        if i == key_start {
            return Err("expected key");
        }
        let key = std::str::from_utf8(&bytes[key_start..i]).map_err(|_| "non-utf8 key")?;
        let key = key.to_ascii_lowercase();

        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] != b'=' {
            return Err("expected '='");
        }
        i += 1;
        while i < bytes.len() && bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        if i >= bytes.len() {
            return Err("expected value");
        }

        let value = if bytes[i] == b'"' {
            i += 1;
            let mut buf = String::new();
            while i < bytes.len() {
                let b = bytes[i];
                i += 1;
                match b {
                    b'\\' => {
                        if i >= bytes.len() {
                            return Err("invalid escape");
                        }
                        let esc = bytes[i];
                        i += 1;
                        buf.push(esc as char);
                    }
                    b'"' => break,
                    _ => buf.push(b as char),
                }
            }
            buf
        } else {
            let v_start = i;
            while i < bytes.len() && bytes[i] != b',' {
                i += 1;
            }
            let raw = std::str::from_utf8(&bytes[v_start..i]).map_err(|_| "non-utf8 value")?;
            raw.trim().to_string()
        };

        out.insert(key, value);
    }

    Ok(out)
}

fn hash_hex(alg: DigestAlgorithm, args: fmt::Arguments<'_>) -> String {
    let s = args.to_string();
    match alg {
        DigestAlgorithm::Md5 | DigestAlgorithm::Md5Sess => {
            let d = md5(s.as_bytes());
            hex_lower(&d)
        }
        DigestAlgorithm::Sha256 | DigestAlgorithm::Sha256Sess => {
            let d = crate::password::sha256(s.as_bytes());
            hex_lower(&d)
        }
    }
}

fn hex_lower<const N: usize>(bytes: &[u8; N]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = Vec::with_capacity(N * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize]);
        out.push(HEX[(b & 0x0f) as usize]);
    }
    String::from_utf8(out).expect("hex is ascii")
}

// =============================================================================
// MD5 (minimal, pure Rust)
// =============================================================================

fn md5(data: &[u8]) -> [u8; 16] {
    // RFC 1321.
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    let bit_len = (data.len() as u64) * 8;
    let mut msg = Vec::with_capacity(((data.len() + 9 + 63) / 64) * 64);
    msg.extend_from_slice(data);
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let j = i * 4;
            *word = u32::from_le_bytes([chunk[j], chunk[j + 1], chunk[j + 2], chunk[j + 3]]);
        }

        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };

            let tmp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g]))
                    .rotate_left(S[i]),
            );
            a = tmp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a0.to_le_bytes());
    out[4..8].copy_from_slice(&b0.to_le_bytes());
    out[8..12].copy_from_slice(&c0.to_le_bytes());
    out[12..16].copy_from_slice(&d0.to_le_bytes());
    out
}

const S: [u32; 64] = [
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14,
    20, 5, 9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11,
    16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
];

const K: [u32; 64] = [
    0xd76aa478,
    0xe8c7b756,
    0x242070db,
    0xc1bdceee,
    0xf57c0faf,
    0x4787c62a,
    0xa8304613,
    0xfd469501,
    0x698098d8,
    0x8b44f7af,
    0xffff5bb1,
    0x895cd7be,
    0x6b901122,
    0xfd987193,
    0xa679438e,
    0x49b40821,
    0xf61e2562,
    0xc040b340,
    0x265e5a51,
    0xe9b6c7aa,
    0xd62f105d,
    0x02441453,
    0xd8a1e681,
    0xe7d3fbc8,
    0x21e1cde6,
    0xc33707d6,
    0xf4d50d87,
    0x455a14ed,
    0xa9e3e905,
    0xfcefa3f8,
    0x676f02d9,
    0x8d2a4c8a,
    0xfffa3942,
    0x8771f681,
    0x6d9d6122,
    0xfde5380c,
    0xa4beea44,
    0x4bdecfa9,
    0xf6bb4b60,
    0xbebfbc70,
    0x289b7ec6,
    0xeaa127fa,
    0xd4ef3085,
    0x04881d05,
    0xd9d4d039,
    0xe6db99e5,
    0x1fa27cf8,
    0xc4ac5665,
    0xf4292244,
    0x432aff97,
    0xab9423a7,
    0xfc93a039,
    0x655b59c3,
    0x8f0ccc92,
    0xffeff47d,
    0x85845dd1,
    0x6fa87e4f,
    0xfe2ce6e0,
    0xa3014314,
    0x4e0811a1,
    0xf7537e82,
    0xbd3af235,
    0x2ad7d2bb,
    0xeb86d391,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc_2617_mufasa_vector_md5_auth() {
        // RFC 2617 example.
        let hdr = concat!(
            "Digest username=\"Mufasa\",",
            " realm=\"testrealm@host.com\",",
            " nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\",",
            " uri=\"/dir/index.html\",",
            " qop=auth,",
            " nc=00000001,",
            " cnonce=\"0a4f113b\",",
            " response=\"6629fae49393a05397450978507c4ef1\",",
            " opaque=\"5ccc069c403ebaf9f0171e9517f40e41\""
        );

        let d = DigestAuth::parse(hdr).expect("parse");
        assert_eq!(d.algorithm, DigestAlgorithm::Md5);
        assert_eq!(d.qop, Some(DigestQop::Auth));

        let ok = d
            .verify(
                Method::Get,
                "testrealm@host.com",
                "Circle Of Life",
            )
            .expect("verify");
        assert!(ok);
    }

    #[test]
    fn md5_known_vector_empty() {
        // MD5("") = d41d8cd98f00b204e9800998ecf8427e
        let d = md5(b"");
        assert_eq!(hex_lower(&d), "d41d8cd98f00b204e9800998ecf8427e");
    }
}

