use mosaic_core::{
    config::ClientConfig,
    report::{Report, Status},
};
use std::time::Duration;

pub async fn run(c: &ClientConfig, report: &mut Report) {
    let ip = c.server.address.ip();
    let placeholder = match ip {
        std::net::IpAddr::V4(ip) => ip.is_documentation(),
        std::net::IpAddr::V6(ip) => ip.segments()[0..2] == [0x2001, 0xdb8],
    };
    if placeholder || c.server.name.ends_with(".example.net") || c.server.name.ends_with(".invalid")
    {
        report.add(
            "relay.target",
            Status::Blocked,
            "replace documentation relay address and certificate name before deployment",
        );
        return;
    }
    let timeout = Duration::from_secs(5);
    let resolved =
        match tokio::time::timeout(timeout, tokio::net::lookup_host(("example.com", 443))).await {
            Ok(Ok(mut addresses)) => addresses.next().is_some(),
            _ => false,
        };
    report.add(
        "host.dns",
        if resolved { Status::Pass } else { Status::Fail },
        if resolved {
            "ordinary hostname resolution succeeded through the existing resolver"
        } else {
            "ordinary hostname resolution failed or exceeded five seconds"
        },
    );
    // Preserve the environment's existing proxy/egress policy. No socket marks,
    // interface binding, route changes, DNS changes or fallback path are used.
    match reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
    {
        Ok(client) => match client.head("https://example.com/").send().await {
            Ok(response) if response.status().is_success() => report.add(
                "host.https",
                Status::Pass,
                "ordinary HTTPS with certificate verification succeeded via existing egress policy",
            ),
            _ => report.add(
                "host.https",
                Status::Fail,
                "ordinary HTTPS check failed or exceeded five seconds",
            ),
        },
        Err(_) => report.add(
            "host.https",
            Status::Fail,
            "cannot initialize verified HTTPS client",
        ),
    }
    report.add("relay.deployment", Status::Blocked, "relay SSH, inbound UDP 443 and /dev/net/tun require dedicated-relay evidence; TCP/UDP socket creation does not prove QUIC reachability");
    report.add("node.preservation_v", Status::Blocked, "requires identified active VPN, five-minute control sample and before/during/after node checks");
    report.add("local.network_preservation", Status::Blocked, "independent before/after routes, resolver, firewall and listener inventory required for deployment gate");
}
