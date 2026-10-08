use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::net::Ipv4Addr;

pub const OWNED_TABLES: [(&str, &str); 2] = [("inet", "mosaic_forward"), ("ip", "mosaic_nat")];
pub const EGRESS: &str = "mosaic_egress";
pub const BLOCKED: [&str; 8] = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "224.0.0.0/3",
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Target {
    pub family: String,
    pub table: String,
    pub chain: String,
}

pub struct Plan<'a> {
    pub tun: &'a str,
    pub wan: &'a str,
    pub client: Ipv4Addr,
    pub local_networks: &'a [String],
    pub forwarding_was_enabled: bool,
    pub targets: &'a [Target],
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub fn interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.')
}

pub fn network(value: &str) -> bool {
    value.split_once('/').is_some_and(|(ip, prefix)| {
        ip.parse::<Ipv4Addr>().is_ok() && prefix.parse::<u8>().is_ok_and(|p| p <= 32)
    })
}

pub fn targets(items: &[Value]) -> Result<Vec<Target>> {
    let mut targets = Vec::new();
    for item in items {
        let Some(chain) = item.get("chain") else {
            continue;
        };
        let family = chain["family"].as_str().unwrap_or_default();
        let table = chain["table"].as_str().unwrap_or_default();
        if OWNED_TABLES.contains(&(family, table)) || chain["name"] == EGRESS {
            continue;
        }
        if chain["hook"] != "forward" || !matches!(family, "ip" | "inet") {
            continue;
        }
        ensure!(
            chain["type"] == "filter",
            "unsupported forwarding chain type; review the firewall first"
        );
        let name = chain["name"].as_str().unwrap_or_default();
        ensure!(
            identifier(table) && identifier(name),
            "unsupported firewall identifier; review the firewall first"
        );
        targets.push(Target {
            family: family.into(),
            table: table.into(),
            chain: name.into(),
        });
    }
    Ok(targets)
}

fn tables(targets: &[Target]) -> Vec<(&str, &str)> {
    let mut tables: Vec<(&str, &str)> = targets
        .iter()
        .map(|t| (t.family.as_str(), t.table.as_str()))
        .collect();
    tables.sort();
    tables.dedup();
    tables
}

pub fn rules(plan: &Plan) -> String {
    let Plan {
        tun, wan, client, ..
    } = *plan;
    let blocked = BLOCKED
        .iter()
        .map(|n| n.to_string())
        .chain(plan.local_networks.iter().cloned())
        .collect::<Vec<_>>()
        .join(", ");
    let allowed = [
        format!("iifname \"{tun}\" oifname \"{wan}\" ip saddr {client} counter accept"),
        format!(
            "iifname \"{wan}\" oifname \"{tun}\" ip daddr {client} ct state established,related counter accept"
        ),
    ];
    let mut lines = vec![
        "add table inet mosaic_forward".to_string(),
        "add chain inet mosaic_forward forward { type filter hook forward priority -10; policy accept; }".to_string(),
        format!("add rule inet mosaic_forward forward iifname \"{tun}\" ip saddr != {client} counter drop"),
        format!("add rule inet mosaic_forward forward iifname \"{tun}\" ip daddr {{ {blocked} }} counter drop"),
    ];
    lines.extend(
        allowed
            .iter()
            .map(|rule| format!("add rule inet mosaic_forward forward {rule}")),
    );
    lines.extend([
        format!("add rule inet mosaic_forward forward iifname \"{tun}\" counter drop"),
        format!("add rule inet mosaic_forward forward oifname \"{tun}\" counter drop"),
    ]);
    if !plan.forwarding_was_enabled {
        lines.push("add rule inet mosaic_forward forward counter drop".to_string());
    }
    lines.extend([
        "add chain inet mosaic_forward input { type filter hook input priority -10; policy accept; }".to_string(),
        format!("add rule inet mosaic_forward input iifname \"{tun}\" icmp type echo-request counter accept"),
        format!("add rule inet mosaic_forward input iifname \"{tun}\" ct state established,related counter accept"),
        format!("add rule inet mosaic_forward input iifname \"{tun}\" counter drop"),
        "add table ip mosaic_nat".to_string(),
        "add chain ip mosaic_nat postrouting { type nat hook postrouting priority srcnat; policy accept; }".to_string(),
        format!("add rule ip mosaic_nat postrouting iifname \"{tun}\" oifname \"{wan}\" ip saddr {client} counter masquerade"),
    ]);
    for (family, table) in tables(plan.targets) {
        lines.push(format!("add chain {family} {table} {EGRESS}"));
        lines.extend(
            allowed
                .iter()
                .map(|rule| format!("add rule {family} {table} {EGRESS} {rule}")),
        );
    }
    for t in plan.targets {
        lines.push(format!(
            "insert rule {} {} {} jump {EGRESS}",
            t.family, t.table, t.chain
        ));
    }
    lines.join("\n") + "\n"
}

pub fn removal(items: &[Value]) -> String {
    let mut lines = Vec::new();
    for item in items {
        let Some(rule) = item.get("rule") else {
            continue;
        };
        let jumps = rule["expr"].as_array().is_some_and(|expressions| {
            expressions
                .iter()
                .any(|expression| expression["jump"]["target"] == EGRESS)
        });
        let family = rule["family"].as_str().unwrap_or_default();
        let table = rule["table"].as_str().unwrap_or_default();
        let chain = rule["chain"].as_str().unwrap_or_default();
        if jumps
            && identifier(table)
            && identifier(chain)
            && matches!(family, "ip" | "inet")
            && let Some(handle) = rule["handle"].as_u64()
        {
            lines.push(format!(
                "delete rule {family} {table} {chain} handle {handle}"
            ));
        }
    }
    for item in items {
        let chain = &item["chain"];
        let family = chain["family"].as_str().unwrap_or_default();
        let table = chain["table"].as_str().unwrap_or_default();
        if chain["name"] == EGRESS && matches!(family, "ip" | "inet") && identifier(table) {
            lines.push(format!("flush chain {family} {table} {EGRESS}"));
            lines.push(format!("delete chain {family} {table} {EGRESS}"));
        }
    }
    for (family, table) in OWNED_TABLES {
        let present = items
            .iter()
            .any(|item| item["table"]["family"] == family && item["table"]["name"] == table);
        if present {
            lines.push(format!("delete table {family} {table}"));
        }
    }
    if lines.is_empty() {
        String::new()
    } else {
        lines.join("\n") + "\n"
    }
}

pub fn ufw_enabled(settings: &str) -> bool {
    settings.lines().any(|line| {
        line.trim()
            .strip_prefix("ENABLED=")
            .is_some_and(|value| value.trim().trim_matches('"').eq_ignore_ascii_case("yes"))
    })
}

pub fn legacy_compatible(saved: &str) -> bool {
    !saved.lines().any(|line| {
        line.starts_with("-A ")
            || (line.starts_with(":FORWARD ") && !line.starts_with(":FORWARD ACCEPT "))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn target() -> Target {
        Target {
            family: "inet".into(),
            table: "filter".into(),
            chain: "forward".into(),
        }
    }

    fn plan<'a>(targets: &'a [Target], networks: &'a [String], enabled: bool) -> Plan<'a> {
        Plan {
            tun: "mosaic0",
            wan: "eth0",
            client: Ipv4Addr::new(10, 77, 0, 2),
            local_networks: networks,
            forwarding_was_enabled: enabled,
            targets,
        }
    }

    #[test]
    fn rules_scope_traffic_to_the_tunnel_client_and_public_destinations() {
        let networks = vec!["203.0.113.0/24".to_string()];
        let targets = [target()];
        let script = rules(&plan(&targets, &networks, false));
        assert!(script.contains("iifname \"mosaic0\" ip saddr != 10.77.0.2 counter drop"));
        assert!(script.contains("169.254.0.0/16"));
        assert!(script.contains("203.0.113.0/24 } counter drop"));
        assert!(script.contains("oifname \"eth0\" ip saddr 10.77.0.2 counter masquerade"));
        assert!(script.contains("add rule inet mosaic_forward forward counter drop"));
        assert!(
            script.contains("add rule inet mosaic_forward input iifname \"mosaic0\" counter drop")
        );
        assert!(script.contains("add chain inet filter mosaic_egress"));
        assert!(script.contains("insert rule inet filter forward jump mosaic_egress"));
        assert!(!script.contains("comment"));
        assert!(!script.contains("443"));
        let existing = rules(&plan(&[], &networks, true));
        assert!(!existing.contains("add rule inet mosaic_forward forward counter drop"));
        assert!(!existing.contains("mosaic_egress"));
    }

    #[test]
    fn targets_include_only_foreign_forward_filter_chains() {
        let items = vec![
            json!({"chain": {"family": "inet", "table": "filter", "name": "forward", "type": "filter", "hook": "forward"}}),
            json!({"chain": {"family": "inet", "table": "filter", "name": "input", "type": "filter", "hook": "input"}}),
            json!({"chain": {"family": "inet", "table": "mosaic_forward", "name": "forward", "type": "filter", "hook": "forward"}}),
            json!({"chain": {"family": "ip6", "table": "filter", "name": "forward", "type": "filter", "hook": "forward"}}),
        ];
        assert_eq!(targets(&items).unwrap(), vec![target()]);
        let unsupported = vec![
            json!({"chain": {"family": "ip", "table": "nat", "name": "forward", "type": "nat", "hook": "forward"}}),
        ];
        assert!(targets(&unsupported).is_err());
        let unsafe_name = vec![
            json!({"chain": {"family": "ip", "table": "filter", "name": "bad name", "type": "filter", "hook": "forward"}}),
        ];
        assert!(targets(&unsafe_name).is_err());
    }

    #[test]
    fn removal_deletes_owned_state_and_every_jump_to_it() {
        let items = vec![
            json!({"table": {"family": "inet", "name": "mosaic_forward"}}),
            json!({"table": {"family": "ip", "name": "mosaic_nat"}}),
            json!({"chain": {"family": "inet", "table": "filter", "name": "mosaic_egress"}}),
            json!({"rule": {"family": "inet", "table": "filter", "chain": "forward", "handle": 7, "expr": [{"jump": {"target": "mosaic_egress"}}]}}),
            json!({"rule": {"family": "inet", "table": "filter", "chain": "forward", "handle": 8, "expr": [{"accept": null}]}}),
            json!({"rule": {"family": "inet", "table": "filter", "chain": "other", "handle": 9, "expr": [{"jump": {"target": "mosaic_egress"}}]}}),
        ];
        let script = removal(&items);
        assert!(script.contains("delete rule inet filter forward handle 7"));
        assert!(!script.contains("handle 8"));
        assert!(script.contains("delete rule inet filter other handle 9"));
        assert!(script.contains("delete chain inet filter mosaic_egress"));
        assert!(script.contains("delete table inet mosaic_forward"));
        assert!(script.contains("delete table ip mosaic_nat"));
        assert!(removal(&[]).is_empty());
    }

    #[test]
    fn legacy_iptables_must_be_empty_with_accepting_forward_policy() {
        assert!(legacy_compatible(""));
        assert!(legacy_compatible(
            "*filter\n:INPUT ACCEPT [0:0]\n:FORWARD ACCEPT [0:0]\nCOMMIT\n"
        ));
        assert!(!legacy_compatible("*filter\n:FORWARD DROP [0:0]\nCOMMIT\n"));
        assert!(!legacy_compatible("*filter\n-A INPUT -j ACCEPT\nCOMMIT\n"));
    }

    #[test]
    fn ufw_is_enabled_only_by_its_setting() {
        assert!(ufw_enabled("# c\nENABLED=yes\n"));
        assert!(ufw_enabled("ENABLED=\"yes\""));
        assert!(!ufw_enabled("ENABLED=no\n"));
        assert!(!ufw_enabled(""));
    }

    #[test]
    fn networks_and_names_are_validated() {
        assert!(network("203.0.113.0/24"));
        assert!(!network("203.0.113.0/33"));
        assert!(!network("eth0; drop"));
        assert!(interface("eth0"));
        assert!(!interface("eth0\" accept"));
    }
}
