use crate::api::config::{Config, ConfigError};
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use azure_core::http::{RequestContent, Url};
use azure_identity::ManagedIdentityCredential;
use azure_storage_blob::clients::{BlobClient, BlobServiceClient};
use azure_storage_blob::models::BlockBlobClientUploadOptions;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::Mac;
use std::sync::Arc;
use uuid::Uuid;

pub const BLOB_PATH_PREFIX: &str = "products/";

const OPERATION_SAS_TTL_MINUTES: u64 = 5;
const SIGNED_VERSION: &str = "2021-12-02";

pub fn is_blob_path(uri: &str) -> bool {
    uri.starts_with(BLOB_PATH_PREFIX)
}

#[derive(Debug)]
pub enum BlobStoreError {
    NotConfigured,
    Config(ConfigError),
    Auth(String),
    Upload(String),
    Delete(String),
    SasUnavailable,
    Signing(String),
}

impl std::fmt::Display for BlobStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlobStoreError::NotConfigured => {
                write!(f, "Blob storage is not configured")
            }
            BlobStoreError::Config(e) => write!(f, "Blob storage configuration error: {}", e),
            BlobStoreError::Auth(msg) => write!(f, "Blob storage authentication error: {}", msg),
            BlobStoreError::Upload(msg) => write!(f, "Blob upload failed: {}", msg),
            BlobStoreError::Delete(msg) => write!(f, "Blob delete failed: {}", msg),
            BlobStoreError::SasUnavailable => write!(
                f,
                "Cannot mint a SAS URL without an AZURE_STORAGE_ACCOUNT_KEY"
            ),
            BlobStoreError::Signing(msg) => write!(f, "SAS signing failed: {}", msg),
        }
    }
}

impl std::error::Error for BlobStoreError {}

#[async_trait]
pub trait BlobStore: Send + Sync {
    /// Uploads bytes and returns the generated blob name.
    async fn upload(&self, bytes: &[u8], content_type: &str) -> Result<String, BlobStoreError>;

    /// Deletes a blob by name.
    async fn delete(&self, blob_name: &str) -> Result<(), BlobStoreError>;

    /// Returns a short-lived read-only SAS URL for a blob.
    async fn mint_read_url(
        &self,
        blob_name: &str,
        ttl_minutes: u64,
    ) -> Result<String, BlobStoreError>;

    /// Whether the store has the minimum configuration to perform operations.
    fn is_configured(&self) -> bool;
}

pub struct AzureBlobStore {
    account: Option<String>,
    container: Option<String>,
    account_key: Option<String>,
    service_client: Option<BlobServiceClient>,
}

impl AzureBlobStore {
    pub fn new() -> Self {
        match Self::try_new() {
            Ok(store) => store,
            Err(error) => {
                tracing::error!("Failed to initialize Azure Blob Storage: {}", error);
                Self::disabled()
            }
        }
    }

    pub fn try_new() -> Result<Self, BlobStoreError> {
        let config = Config::get().map_err(BlobStoreError::Config)?;
        let account = config.azure_storage_account.clone();
        let container = config.azure_storage_container.clone();
        let account_key = config.azure_storage_account_key.clone();

        let (Some(account), Some(container)) = (account, container) else {
            return Ok(Self::disabled());
        };

        let service_client = match &account_key {
            Some(_) => None,
            None => {
                let credential: Arc<dyn TokenCredential> = ManagedIdentityCredential::new(None)
                    .map_err(|error| BlobStoreError::Auth(error.to_string()))?;
                let service_url = Url::parse(&format!(
                    "https://{account}.blob.core.windows.net/"
                ))
                .map_err(|error| BlobStoreError::Auth(error.to_string()))?;
                let client = BlobServiceClient::new(service_url, Some(credential), None)
                    .map_err(|error| BlobStoreError::Auth(error.to_string()))?;
                Some(client)
            }
        };

        Ok(Self {
            account: Some(account),
            container: Some(container),
            account_key,
            service_client,
        })
    }

    pub fn disabled() -> Self {
        Self {
            account: None,
            container: None,
            account_key: None,
            service_client: None,
        }
    }

    fn blob_client_with_sas(
        &self,
        blob_name: &str,
        permissions: &str,
        ttl_minutes: u64,
    ) -> Result<BlobClient, BlobStoreError> {
        let (account, container) = match (&self.account, &self.container) {
            (Some(account), Some(container)) => (account, container),
            _ => return Err(BlobStoreError::NotConfigured),
        };
        let key = self
            .account_key
            .as_ref()
            .ok_or(BlobStoreError::SasUnavailable)?;
        let query = Self::service_sas(key, account, container, blob_name, permissions, ttl_minutes)?;
        let url = Url::parse(&format!(
            "https://{account}.blob.core.windows.net/{container}/{blob_name}?{query}"
        ))
        .map_err(|error| BlobStoreError::Signing(error.to_string()))?;
        BlobClient::new(url, None, None)
            .map_err(|error| BlobStoreError::Auth(error.to_string()))
    }

    fn service_sas(
        key: &str,
        account: &str,
        container: &str,
        blob_name: &str,
        permissions: &str,
        ttl_minutes: u64,
    ) -> Result<String, BlobStoreError> {
        let decoded_key = BASE64
            .decode(key)
            .map_err(|error| BlobStoreError::Signing(format!("invalid account key: {error}")))?;

        let now = chrono::Utc::now();
        let started_at = (now - chrono::Duration::minutes(5))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let expires_at = (now + chrono::Duration::minutes(ttl_minutes as i64))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let canonical_resource = format!("/blob/{account}/{container}/{blob_name}");

        let string_to_sign = [
            permissions.to_string(),
            started_at.clone(),
            expires_at.clone(),
            canonical_resource,
            String::new(),
            String::new(),
            "https".to_string(),
            SIGNED_VERSION.to_string(),
            "b".to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ]
        .join("\n");

        let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(&decoded_key)
            .map_err(|error| BlobStoreError::Signing(format!("failed to create HMAC: {error}")))?;
        mac.update(string_to_sign.as_bytes());
        let signature = BASE64.encode(mac.finalize().into_bytes());
        let encoded_signature =
            percent_encoding::utf8_percent_encode(&signature, percent_encoding::NON_ALPHANUMERIC);

        Ok(format!(
            "sv={SIGNED_VERSION}&st={started_at}&se={expires_at}&sr=b&sp={permissions}&spr=https&sig={encoded_signature}"
        ))
    }
}

impl Default for AzureBlobStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BlobStore for AzureBlobStore {
    async fn upload(&self, bytes: &[u8], content_type: &str) -> Result<String, BlobStoreError> {
        let extension = match content_type {
            "image/jpeg" => "jpg",
            "image/png" => "png",
            "image/webp" => "webp",
            _ => return Err(BlobStoreError::Upload(format!("unsupported content type {content_type}"))),
        };
        let blob_name = format!("{BLOB_PATH_PREFIX}{}.{extension}", Uuid::new_v4());

        let client = match &self.service_client {
            Some(service_client) => {
                let container = self
                    .container
                    .as_ref()
                    .ok_or(BlobStoreError::NotConfigured)?;
                service_client.blob_client(container, &blob_name)
            }
            None => self.blob_client_with_sas(&blob_name, "cw", OPERATION_SAS_TTL_MINUTES)?,
        };

        let options = BlockBlobClientUploadOptions {
            blob_content_type: Some(content_type.to_string()),
            ..Default::default()
        };
        client
            .upload(RequestContent::from(bytes.to_vec()), Some(options))
            .await
            .map_err(|error| BlobStoreError::Upload(error.to_string()))?;
        Ok(blob_name)
    }

    async fn delete(&self, blob_name: &str) -> Result<(), BlobStoreError> {
        let client = match &self.service_client {
            Some(service_client) => {
                let container = self
                    .container
                    .as_ref()
                    .ok_or(BlobStoreError::NotConfigured)?;
                service_client.blob_client(container, blob_name)
            }
            None => self.blob_client_with_sas(blob_name, "d", OPERATION_SAS_TTL_MINUTES)?,
        };
        client
            .delete(None)
            .await
            .map_err(|error| BlobStoreError::Delete(error.to_string()))?;
        Ok(())
    }

    async fn mint_read_url(
        &self,
        blob_name: &str,
        ttl_minutes: u64,
    ) -> Result<String, BlobStoreError> {
        let (account, container) = match (&self.account, &self.container) {
            (Some(account), Some(container)) => (account, container),
            _ => return Err(BlobStoreError::NotConfigured),
        };
        let key = self
            .account_key
            .as_ref()
            .ok_or(BlobStoreError::SasUnavailable)?;
        let query = Self::service_sas(key, account, container, blob_name, "r", ttl_minutes)?;
        Ok(format!(
            "https://{account}.blob.core.windows.net/{container}/{blob_name}?{query}"
        ))
    }

    fn is_configured(&self) -> bool {
        matches!((&self.account, &self.container), (Some(_), Some(_)))
    }
}
