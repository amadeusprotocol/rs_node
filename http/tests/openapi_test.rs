use http::openapi::ApiDoc;
use utoipa::OpenApi;

#[tokio::test]
async fn test_openapi_yaml_generation() {
    let openapi = ApiDoc::openapi();
    let yaml = serde_yaml::to_string(&openapi).unwrap();
    assert!(!yaml.is_empty());
    assert!(yaml.contains("openapi:"));
    assert!(yaml.contains("Amadeus Node HTTP API"));
    println!("Generated OpenAPI YAML:\n{}", yaml);
}

#[tokio::test]
async fn test_openapi_struct() {
    let openapi = ApiDoc::openapi();
    assert_eq!(openapi.info.title, "Amadeus Node HTTP API");
    assert_eq!(openapi.info.version, "1.1.9");
    assert!(!openapi.paths.paths.is_empty());
}
