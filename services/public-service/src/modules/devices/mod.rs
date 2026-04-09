use chrono::Utc;
use std::collections::HashMap;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct DeviceData {
    pub device_id: String,
    pub platform: String,
    pub nickname: String,
    pub created_at: i64,
}

pub fn create_device(
    devices: &mut HashMap<String, Vec<DeviceData>>,
    user_id: &str,
    platform: &str,
    nickname: &str,
) -> DeviceData {
    let device = DeviceData {
        device_id: Uuid::new_v4().to_string(),
        platform: platform.to_string(),
        nickname: nickname.to_string(),
        created_at: Utc::now().timestamp(),
    };

    devices
        .entry(user_id.to_string())
        .or_default()
        .push(device.clone());

    device
}

pub fn list_devices(devices: &HashMap<String, Vec<DeviceData>>, user_id: &str) -> Vec<DeviceData> {
    devices.get(user_id).cloned().unwrap_or_default()
}
