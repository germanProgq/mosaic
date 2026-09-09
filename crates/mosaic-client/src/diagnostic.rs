use mosaic_core::{
    config::ClientConfig,
    quic,
    report::{Report, Status},
    session,
};

pub async fn run(
    c: &ClientConfig,
    case: &str,
    options: &quic::DatagramOptions,
    report: &mut Report,
) {
    if let Err(e) = options.validate() {
        report.add("diagnostic.options", Status::Fail, &e.to_string());
        return;
    }
    let placeholder = match c.server.address.ip() {
        std::net::IpAddr::V4(ip) => ip.is_documentation(),
        std::net::IpAddr::V6(ip) => ip.segments()[0..2] == [0x2001, 0xdb8],
    };
    if placeholder {
        report.add(
            "relay.target",
            Status::Blocked,
            "replace documentation relay address before networking",
        );
        return;
    }
    report.add(
        "quic.scope",
        Status::Pass,
        "authenticated diagnostics; TUN and fetch unavailable; host routing unchanged",
    );
    let client = match quic::connect(c).await {
        Ok(client) => client,
        Err(_) => {
            // Do not print peer-controlled TLS errors/reason strings or configuration values.
            report.add("quic.handshake", Status::Fail, "verified QUIC connection failed or exceeded five seconds; check trust, server name, ALPN and existing UDP egress policy");
            return;
        }
    };
    report.add(
        "quic.handshake",
        Status::Pass,
        "certificate trust/name and mosaic-poc/2 ALPN verified within five seconds; 0-RTT disabled",
    );
    let ready = match session::authorize(&client.connection, c).await {
        Ok(ready) => ready,
        Err(e) => {
            let detail = if e.is::<session::SizeError>() {
                "datagram size limit must fit 1112 bytes before Ready or TUN setup"
            } else {
                "session authorization rejected, invalid control framing or five-second deadline exceeded"
            };
            report.add("session.ready", Status::Fail, detail);
            return;
        }
    };
    report.add(
        "session.ready",
        Status::Pass,
        "SessionInit authorized; connection-bound SessionReady values confirmed by ClientReady",
    );
    report.add(
        "session.datagram_limit",
        Status::Pass,
        &format!(
            "both send directions fit 1112 bytes; agreed limit {} bytes",
            ready.send_limit
        ),
    );
    report.add("quic.handshake_visibility", Status::Pass, "TLS Initial server name and offered ALPN mosaic-poc/2 are observable; token is encrypted application data; this run does not capture the outer handshake");
    if case == "session" {
        match quic::echo(&client.connection, b"authenticated session probe").await {
            Ok(()) => report.add("session.echo", Status::Pass, "byte-exact echo after Ready"),
            Err(_) => report.add("session.echo", Status::Fail, "authenticated echo failed"),
        }
        return;
    }
    if case == "datagram-echo" {
        match quic::datagram_suite(&client.connection, options, c.test_limits.as_ref().map_or(1.0, |l| l.max_mbps)).await {
            Ok(received) => report.add("quic.datagram_echo", Status::Pass, &format!("{received}/{} unique byte-exact replies of {} bytes; receive window ends three seconds after final send", options.count, options.size)),
            Err(_) => report.add("quic.datagram_echo", Status::Fail, "invalid datagram, excessive loss, size error or diagnostic deadline exceeded"),
        }
        return;
    }
    report.add("quic.egress", Status::Pass, if c.server.address.ip().is_loopback() {
        "loopback fixture; unpaced local correctness test, not a throughput benchmark"
    } else {
        "ordinary host UDP egress; request+response payload paced below configured ceiling with QUIC headroom; VPN/direct path not independently verified"
    });
    match quic::echo_suite(
        &client.connection,
        c.test_limits.as_ref().map_or(1.0, |l| l.max_mbps),
    )
    .await
    {
        Ok(outcomes) => {
            for (size, count) in outcomes {
                report.add(&format!("quic.echo.{size}"), Status::Pass, &format!("{count}/100 byte-exact echoes of {size} bytes; up to three simultaneous streams on one connection"));
            }
        }
        Err(_) => report.add(
            "quic.echo",
            Status::Fail,
            "echo mismatch, stream/connection failure or deadline exceeded",
        ),
    }
}
