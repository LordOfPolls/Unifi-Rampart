use mongodb::bson::doc;
use unifi_rampart::mongo;

#[tokio::test]
#[ignore]
async fn test_delete_all_firewall_groups() {
    let connection_url =
        std::env::var("MONGODB_URL").unwrap_or_else(|_| "mongodb://localhost:27018".to_string());

    let client = mongo::connect(&connection_url)
        .await
        .expect("Failed to connect to MongoDB");

    let db = client.database("unifi_rampart_test");

    let col: mongodb::Collection<mongodb::bson::Document> = db.collection("firewallgroup");

    col.delete_many(doc! {}, None).await.unwrap();

    col.insert_one(
        doc! {
            "name": "test_group_1",
            "group_type": "address-group",
            "group_members": ["192.168.1.1", "192.168.1.2"]
        },
        None,
    )
    .await
    .unwrap();

    col.insert_one(
        doc! {
            "name": "test_group_2",
            "group_type": "address-group",
            "group_members": ["10.0.0.1"]
        },
        None,
    )
    .await
    .unwrap();

    let count_before = col.count_documents(doc! {}, None).await.unwrap();
    assert_eq!(count_before, 2);

    let deleted_count = mongo::delete_all_firewall_groups(&db)
        .await
        .expect("Failed to delete firewall groups");

    assert_eq!(deleted_count, 2);

    let count_after = col.count_documents(doc! {}, None).await.unwrap();
    assert_eq!(count_after, 0);
}
