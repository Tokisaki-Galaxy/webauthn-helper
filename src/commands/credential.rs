use crate::errors::AppError;
use crate::schemas::{CredentialListItem, CredentialUpdateData, SuccessResponse};
use crate::storage::*;

pub fn list_credentials(storage: &dyn StorageProvider, username: &str) -> Result<String, AppError> {
    let store = storage.load_credentials()?;

    let items: Vec<CredentialListItem> = if let Some(user_record) = store.users.get(username) {
        user_record
            .credentials
            .iter()
            .map(|c| CredentialListItem {
                credential_id: c.credential_id.clone(),
                username: username.to_string(),
                device_name: c.device_name.clone(),
                created_at: c.created_at.clone(),
                last_used_at: c.last_used_at.clone(),
                backup_eligible: c.backup_eligible,
                user_verified: c.user_verified,
            })
            .collect()
    } else {
        vec![]
    };

    let response = SuccessResponse::new(items);
    Ok(serde_json::to_string(&response)?)
}

pub fn delete_credential(storage: &dyn StorageProvider, credential_id: &str) -> Result<String, AppError> {
    let mut store = storage.load_credentials()?;
    let mut found = false;

    for user_record in store.users.values_mut() {
        let original_len = user_record.credentials.len();
        user_record.credentials.retain(|c| c.credential_id != credential_id);
        if user_record.credentials.len() < original_len {
            found = true;
            break;
        }
    }

    if !found {
        return Err(AppError::CredentialNotFound(credential_id.to_string()));
    }

    storage.save_credentials(&store)?;

    let response = SuccessResponse::new(serde_json::json!({
        "credentialId": credential_id,
        "deleted": true
    }));
    Ok(serde_json::to_string(&response)?)
}

pub fn update_credential(storage: &dyn StorageProvider, credential_id: &str, new_name: &str) -> Result<String, AppError> {
    let mut store = storage.load_credentials()?;
    let mut old_name = None;

    for user_record in store.users.values_mut() {
        for cred in &mut user_record.credentials {
            if cred.credential_id == credential_id {
                old_name = Some(cred.device_name.clone());
                cred.device_name = new_name.to_string();
                break;
            }
        }
        if old_name.is_some() {
            break;
        }
    }

    let old_name = old_name.ok_or_else(|| AppError::CredentialNotFound(credential_id.to_string()))?;

    storage.save_credentials(&store)?;

    let data = CredentialUpdateData {
        credential_id: credential_id.to_string(),
        old_name,
        new_name: new_name.to_string(),
    };
    let response = SuccessResponse::new(data);
    Ok(serde_json::to_string(&response)?)
}

pub fn cleanup_challenges(storage: &dyn StorageProvider) -> Result<String, AppError> {
    let count = storage.cleanup_challenges()?;
    let response = SuccessResponse::new(serde_json::json!({
        "removedCount": count
    }));
    Ok(serde_json::to_string(&response)?)
}
