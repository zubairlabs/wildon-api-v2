use contracts::wildon::storage::v1::ObjectStatus;

pub fn can_create_download(status: ObjectStatus) -> bool {
    matches!(status, ObjectStatus::Available)
}
