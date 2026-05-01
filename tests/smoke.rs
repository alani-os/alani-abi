#[test]
fn repository_identity_is_stable() {
    assert_eq!(alani_abi::repository_name(), "alani-abi");
    assert!(!alani_abi::module_names().is_empty());
}
