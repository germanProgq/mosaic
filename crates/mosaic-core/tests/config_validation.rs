use mosaic_core::config::{ClientConfig, RelayConfig, read_token};
use serde_json::{Value, json};
use std::{fs, path::Path};
use tempfile::TempDir;

fn example(name: &str) -> Value {
    serde_json::from_str(
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(format!("../../configs/{name}.example.json")),
        )
        .unwrap(),
    )
    .unwrap()
}
fn write(dir: &TempDir, value: &Value) -> std::path::PathBuf {
    let path = dir.path().join("client.json");
    fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
    path
}
#[test]
fn all_examples_parse() {
    let dir = TempDir::new().unwrap();
    for name in ["client", "client-node"] {
        ClientConfig::load(&write(&dir, &example(name))).unwrap();
    }
    RelayConfig::load(&write(&dir, &example("relay"))).unwrap();
}
#[test]
fn client_rejects_unsafe_or_unknown_settings_without_echoing_values() {
    let dir = TempDir::new().unwrap();
    for (pointer, bad) in [
        ("/version", json!(1)),
        ("/mode", json!("SENSITIVE_CANARY")),
        ("/network/outbound_only", json!(false)),
        ("/network/change_host_network", json!(true)),
        ("/transport/alpn", json!("h3")),
        ("/transport/idle_timeout_s", json!(999)),
        ("/transport/keepalive_s", json!(0)),
        ("/limits/max_control_bytes", json!(4097)),
        ("/limits/queue_packets", json!(2049)),
        ("/limits/queue_packets", json!(0)),
        ("/transport/idle_timeout_s", json!(3)),
        ("/server/name", json!("https://secret@host/")),
        ("/server/address", json!("0.0.0.0:443")),
    ] {
        let mut value = example("client");
        *value.pointer_mut(pointer).unwrap() = bad;
        let err = ClientConfig::load(&write(&dir, &value))
            .err()
            .expect(pointer)
            .to_string();
        assert!(!err.contains("SENSITIVE_CANARY"));
    }
    for parent in [
        "",
        "/server",
        "/auth",
        "/transport",
        "/tls",
        "/network",
        "/limits",
    ] {
        let mut value = example("client");
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("SENSITIVE_CANARY".into(), json!("SENSITIVE_CANARY"));
        let err = ClientConfig::load(&write(&dir, &value))
            .err()
            .unwrap()
            .to_string();
        assert!(!err.contains("SENSITIVE_CANARY"));
    }
}
#[test]
fn isolation_rejects_bypasses_and_invalid_subnets() {
    let dir = TempDir::new().unwrap();
    for (pointer, bad) in [
        ("/isolation/namespace", json!("existing-vpn")),
        (
            "/isolation/transport_socket",
            json!("created_in_tun_namespace"),
        ),
        ("/isolation/preserve_existing_vpn", json!(false)),
        ("/isolation/host_network_changes", json!("allowed")),
        ("/tunnel/address", json!("10.77.0.0/30")),
        ("/tunnel/peer", json!("10.78.0.1")),
        ("/tunnel/name", json!("eth0")),
        ("/tunnel/mtu", json!(1500)),
        ("/tunnel/ipv6", json!("allow")),
        ("/test_limits/max_mbps", json!(1.1)),
        ("/test_limits/parallel_flows", json!(2)),
        ("/dns/servers", json!([])),
        ("/dns/servers", json!(["127.0.0.53"])),
        ("/dns/servers", json!(["10.77.0.1"])),
        ("/dns/servers", json!(["1.1.1.1", "8.8.8.8"])),
    ] {
        let mut value = example("client-node");
        *value.pointer_mut(pointer).unwrap() = bad;
        assert!(
            ClientConfig::load(&write(&dir, &value)).is_err(),
            "{pointer}"
        );
    }
}
#[test]
fn missing_duplicate_truncated_and_oversized_configs_fail() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("bad.json");
    for bytes in [
        b"{".to_vec(),
        b"{\"version\":2,\"version\":2}".to_vec(),
        vec![b' '; 65537],
    ] {
        fs::write(&path, bytes).unwrap();
        assert!(ClientConfig::load(&path).is_err());
    }
    assert!(ClientConfig::load(&dir.path().join("missing.json")).is_err());
    let mut value = example("client");
    value.as_object_mut().unwrap().remove("network");
    assert!(ClientConfig::load(&write(&dir, &value)).is_err());
}
#[test]
fn credentials_resolve_relative_to_config_and_validate_real_key_pair() {
    let dir = TempDir::new().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["relay.example.net".into()]).unwrap();
    let secrets = dir.path().join("secrets");
    fs::create_dir(&secrets).unwrap();
    fs::write(secrets.join("relay.crt"), cert.cert.pem()).unwrap();
    fs::write(secrets.join("relay.key"), cert.signing_key.serialize_pem()).unwrap();
    fs::write(secrets.join("client.token"), "a5".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for name in ["relay.key", "client.token"] {
            fs::set_permissions(secrets.join(name), fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let c = ClientConfig::load(&write(&dir, &example("client"))).unwrap();
    assert_eq!(c.auth.token_file, secrets.join("client.token"));
    c.check_credentials().unwrap();
    let relay = RelayConfig::load(&write(&dir, &example("relay"))).unwrap();
    relay.check_credentials().unwrap();
    let other = rcgen::generate_simple_self_signed(vec!["other.example.net".into()]).unwrap();
    fs::write(secrets.join("relay.key"), other.signing_key.serialize_pem()).unwrap();
    assert!(relay.check_credentials().is_err());
    fs::write(secrets.join("relay.crt"), "not a cert").unwrap();
    assert!(c.check_credentials().is_err());
}
#[test]
fn tokens_require_exact_hex_length_and_owner_only_permissions() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("token");
    fs::write(&path, "00".repeat(32)).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_token(&path).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    for suffix in ["", "\n", "\r\n"] {
        fs::write(&path, format!("{}{suffix}", "aB".repeat(32))).unwrap();
        assert_eq!(read_token(&path).unwrap(), [0xab; 32]);
    }
    for bad in [
        "a".repeat(63),
        "a".repeat(65),
        "g".repeat(64),
        " ".to_owned() + &"a".repeat(64),
        "a".repeat(100000),
    ] {
        fs::write(&path, bad).unwrap();
        assert!(read_token(&path).is_err());
    }
}
#[test]
fn relay_rejects_unbounded_proxy_and_multiple_tunnel_owners() {
    let dir = TempDir::new().unwrap();
    for (pointer, bad) in [
        ("/tunnel_owners", json!(2)),
        ("/allowed_client", json!("10.77.0.3")),
        ("/fetch/allow/0/host", json!("127.0.0.1")),
        ("/fetch/allow/0/port", json!(80)),
        ("/fetch/max_bytes", json!(33554433)),
    ] {
        let mut value = example("relay");
        *value.pointer_mut(pointer).unwrap() = bad;
        assert!(
            RelayConfig::load(&write(&dir, &value)).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn rate_limits_and_timeouts_are_optional_but_bounded() {
    let dir = TempDir::new().unwrap();
    let mut value = example("client");
    value["limits"]["max_mbps"] = json!(250.0);
    value["limits"]["queue_packets"] = json!(2048);
    value["transport"]["idle_timeout_s"] = json!(8);
    value["transport"]["keepalive_s"] = json!(2);
    let config = ClientConfig::load(&write(&dir, &value)).unwrap();
    assert_eq!(config.limits.max_mbps, Some(250.0));
    for (pointer, bad) in [
        ("/limits/max_mbps", json!(0.0)),
        ("/limits/max_mbps", json!(-5.0)),
        ("/limits/max_mbps", json!(1.0e9)),
        ("/transport/keepalive_s", json!(5)),
    ] {
        let mut value = value.clone();
        *value.pointer_mut(pointer).unwrap() = bad;
        assert!(
            ClientConfig::load(&write(&dir, &value)).is_err(),
            "{pointer}"
        );
    }
    let unlimited = example("client");
    assert_eq!(
        ClientConfig::load(&write(&dir, &unlimited))
            .unwrap()
            .limits
            .max_mbps,
        None
    );
}
#[test]
fn traffic_exceptions_are_native_linux_only_and_validated() {
    let dir = TempDir::new().unwrap();
    let mut native = example("client-native");
    native["tls"]["trust_cert"] = json!("relay.crt");
    native["auth"]["token_file"] = json!("client.token");
    native["exceptions"] = json!({"inbound_replies": true, "services": ["xray.service"]});
    ClientConfig::load(&write(&dir, &native)).unwrap();
    for bad in [
        json!({"inbound_replies": false, "services": []}),
        json!({"inbound_replies": true, "services": ["xray"]}),
        json!({"inbound_replies": true, "services": ["../x.service"]}),
        json!({"inbound_replies": true, "services": ["a\".service"]}),
        json!({"inbound_replies": true, "services": ["a.service", "a.service"]}),
        json!({"inbound_replies": true, "services": ["SENSITIVE_CANARY"], "extra": 1}),
    ] {
        let mut value = native.clone();
        value["exceptions"] = bad;
        let err = ClientConfig::load(&write(&dir, &value)).err().unwrap();
        assert!(!err.to_string().contains("SENSITIVE_CANARY"));
    }
    let mut diagnostic = example("client");
    diagnostic["exceptions"] = json!({"inbound_replies": true, "services": []});
    assert!(ClientConfig::load(&write(&dir, &diagnostic)).is_err());
    assert!(mosaic_core::config::service_name("xray.service"));
    assert!(!mosaic_core::config::service_name("getty@tty1.service"));
    assert!(!mosaic_core::config::service_name(".service"));
    assert!(!mosaic_core::config::service_name("-x.service"));
}
