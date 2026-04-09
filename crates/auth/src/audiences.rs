use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Audience {
    Public,
    Platform,
    Control,
}

impl Audience {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Platform => "platform",
            Self::Control => "control",
        }
    }
}

impl FromStr for Audience {
    type Err = &'static str;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "public" => Ok(Self::Public),
            "platform" => Ok(Self::Platform),
            "control" => Ok(Self::Control),
            _ => Err("unsupported audience"),
        }
    }
}

pub fn is_supported_audience(aud: &str) -> bool {
    Audience::from_str(aud).is_ok()
}

pub fn is_supported_realm(realm: &str) -> bool {
    matches!(realm, "public" | "platform" | "control")
}
