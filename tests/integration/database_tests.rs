#[tokio::test]
#[serial_test::serial]
pub async fn test_database_connection() {
    let database = arrow_server_lib::data::database::Database::new().await;

    // Attempt to get a connection from the pool
    let conn = database.get_connection().await;

    assert!(conn.is_ok(), "Failed to get a database connection");
}
