use arrow_server_lib::services::blob_storage_service::AzureBlobStore;
use arrow_server_lib::utils::order_url::{
    OrderUrlError, sign_order_url_with_key, verify_order_url_with_key,
};

const ORDER_SECRET: &str = "test-qr-secret";
const ORDER_ID: i32 = 42;
const ORDER_EXPIRATION: u64 = 1_700_000_000;
const FUTURE_ORDER_EXPIRATION: u64 = 4_000_000_000;
const ACCOUNT_KEY: &str = "dGVzdC1hY2NvdW50LWtleQ==";

// pinned HMAC-SHA256 output; regenerate only if the signing scheme intentionally changes
const ORDER_SIGNATURE: &str = "187a8aa6b41fcd148ab38a78daa61db866d99b18128b67401bd7282f69cadc20";
// pinned HMAC-SHA256 output; regenerate only if the signing scheme intentionally changes
const FUTURE_ORDER_SIGNATURE: &str =
    "7e5b25d6338119816aa0fb6028a7392a251f3b94613636704222261cc05b804f";
// pinned SAS query output; regenerate only if the signing scheme intentionally changes
const SAS_QUERY: &str = "sv=2021-12-02&st=2026-01-02T02:59:05Z&se=2026-01-02T03:19:05Z&sr=b&sp=r&spr=https&sig=gQV1WmFYd7PFV3mmG1OIrhrTIQ0MiZqmtVjbM8eqYH0%3D";

#[test]
fn order_url_sign_vector() {
    let signature = sign_order_url_with_key(ORDER_SECRET, ORDER_ID, ORDER_EXPIRATION).unwrap();
    assert_eq!(signature, ORDER_SIGNATURE);
}

#[test]
fn order_url_verify_round_trip_and_tamper() {
    assert_eq!(
        verify_order_url_with_key(
            ORDER_SECRET,
            ORDER_ID,
            FUTURE_ORDER_EXPIRATION,
            FUTURE_ORDER_SIGNATURE,
        ),
        Ok(())
    );

    let mut tampered = FUTURE_ORDER_SIGNATURE.as_bytes().to_vec();
    tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
    let tampered = String::from_utf8(tampered).unwrap();
    assert_eq!(
        verify_order_url_with_key(ORDER_SECRET, ORDER_ID, FUTURE_ORDER_EXPIRATION, &tampered,),
        Err(OrderUrlError::InvalidSignature)
    );
    assert_eq!(
        verify_order_url_with_key(ORDER_SECRET, ORDER_ID, 1, FUTURE_ORDER_SIGNATURE),
        Err(OrderUrlError::Expired)
    );
}

#[test]
fn service_sas_vector() {
    let now = chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    let query = AzureBlobStore::service_sas_at(
        ACCOUNT_KEY,
        "acct",
        "products",
        "products/abc.png",
        "r",
        15,
        now,
    )
    .unwrap();
    assert_eq!(query, SAS_QUERY);
}
