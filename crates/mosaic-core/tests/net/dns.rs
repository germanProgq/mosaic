use mosaic_core::namespace;

#[test]
fn namespace_dns_has_one_server_and_no_host_resolver_service() {
    assert_eq!(
        namespace::RESOLVER
            .lines()
            .filter(|line| line.starts_with("nameserver "))
            .collect::<Vec<_>>(),
        ["nameserver 1.1.1.1"]
    );
    let original = "passwd: files systemd\ngroup: files\nhosts: files resolve [!UNAVAIL=return] dns\n hosts : mdns4_minimal dns\nnetworks: files\n";
    assert_eq!(
        namespace::name_services(original),
        "passwd: files systemd\ngroup: files\nnetworks: files\nhosts: dns\n"
    );
    assert_eq!(
        namespace::name_services("passwd: files"),
        "passwd: files\nhosts: dns\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires root on a dedicated Linux test host with ip, getent, curl and /dev/net/tun"]
fn linux_private_dns_and_no_escape() {
    use mosaic_core::{config::Tunnel, linux, pump::PacketIo, tun::Tun};
    use std::{
        fs,
        io::{BufRead, BufReader, Write},
        os::unix::process::CommandExt,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    use tokio::time::timeout;

    fn checksum(bytes: &[u8]) -> u16 {
        let sum: u32 = bytes
            .chunks_exact(2)
            .map(|b| u32::from(u16::from_be_bytes([b[0], b[1]])))
            .sum();
        let sum = (sum & 0xffff) + (sum >> 16);
        !((sum & 0xffff) + (sum >> 16)) as u16
    }

    fn dns_reply(packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 40
            || packet[0] != 0x45
            || packet[9] != 17
            || packet[16..20] != [1, 1, 1, 1]
            || packet[22..24] != [0, 53]
        {
            return None;
        }
        let request = &packet[28..];
        let mut end = 12;
        while *request.get(end)? != 0 {
            end += 1 + usize::from(request[end]);
        }
        end += 5;
        if request.get(end - 4..end)? != [0, 1, 0, 1] {
            return None;
        }
        let mut reply = vec![0u8; 28];
        reply.extend_from_slice(&request[..end]);
        reply[30..32].copy_from_slice(&[0x81, 0x80]);
        reply[34..36].copy_from_slice(&[0, 1]);
        reply[36..40].fill(0);
        reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 93, 184, 215, 14]);
        let size = reply.len() as u16;
        reply[0] = 0x45;
        reply[2..4].copy_from_slice(&size.to_be_bytes());
        reply[8] = 64;
        reply[9] = 17;
        reply[12..16].copy_from_slice(&packet[16..20]);
        reply[16..20].copy_from_slice(&packet[12..16]);
        reply[20..22].copy_from_slice(&packet[22..24]);
        reply[22..24].copy_from_slice(&packet[20..22]);
        reply[24..26].copy_from_slice(&(size - 20).to_be_bytes());
        let check = checksum(&reply[..20]);
        reply[10..12].copy_from_slice(&check.to_be_bytes());
        Some(reply)
    }

    assert_eq!(unsafe { libc::geteuid() }, 0);
    if let Ok(mode) = std::env::var("MOSAIC_DNS_FIXTURE") {
        namespace::private_dns().unwrap();
        assert_eq!(
            fs::read_to_string("/etc/resolv.conf").unwrap(),
            namespace::RESOLVER
        );
        assert!(
            fs::OpenOptions::new()
                .write(true)
                .open("/etc/resolv.conf")
                .is_err()
        );
        linux::command("ip", &["link", "set", "lo", "up"]).unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let tun = Tun::create(&Tunnel {
                name: "mosaic0".into(),
                address: "10.77.0.2/30".into(),
                peer: "10.77.0.1".parse().unwrap(),
                mtu: 1100,
                ipv6: "block".into(),
            })
            .unwrap();
            namespace::default_route("mosaic0").unwrap();
            let links = Command::new("ip")
                .args(["-j", "link", "show"])
                .output()
                .unwrap();
            let links: Vec<serde_json::Value> = serde_json::from_slice(&links.stdout).unwrap();
            assert_eq!(links.len(), 2);
            assert!(
                links
                    .iter()
                    .all(|link| link["ifname"] == "lo" || link["ifname"] == "mosaic0")
            );
            if mode == "kill" {
                println!("resolver ready");
                std::io::stdout().flush().unwrap();
                tokio::time::sleep(Duration::from_secs(30)).await;
                panic!("fixture was not killed");
            }
            let mut resolver = Command::new("getent")
                .args(["ahostsv4", "example.com"])
                .env_remove("LOCALDOMAIN")
                .env_remove("RES_OPTIONS")
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut packets = 0;
            timeout(Duration::from_secs(6), async {
                let mut bytes = [0u8; 1100];
                loop {
                    if resolver.try_wait().unwrap().is_some() {
                        break;
                    }
                    tokio::select! {
                        result = tun.receive(&mut bytes) => {
                            if let Some(reply) = dns_reply(&bytes[..result.unwrap()]) {
                                tun.send(&reply).await.unwrap();
                                packets += 1;
                            }
                        },
                        _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                    }
                }
            })
            .await
            .unwrap();
            let output = resolver.wait_with_output().unwrap();
            assert!(output.status.success());
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("93.184.215.14")
            );
            assert!(packets > 0);
            for (program, args) in [
                ("getent", vec!["ahostsv4", "unavailable.example.com"]),
                (
                    "curl",
                    vec![
                        "-q",
                        "--noproxy",
                        "*",
                        "-4fsS",
                        "--max-time",
                        "3",
                        "--resolve",
                        "example.com:443:93.184.215.14",
                        "https://example.com",
                    ],
                ),
            ] {
                let start = Instant::now();
                let mut command = Command::new(program)
                    .args(args)
                    .env_remove("LOCALDOMAIN")
                    .env_remove("RES_OPTIONS")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap();
                loop {
                    if let Some(status) = command.try_wait().unwrap() {
                        assert!(
                            !status.success(),
                            "application escaped the unresponsive TUN"
                        );
                        break;
                    }
                    if start.elapsed() > Duration::from_secs(8) {
                        command.kill().unwrap();
                        command.wait().unwrap();
                        panic!("unavailable request exceeded deadline");
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            }
        });
        return;
    }
    let resolver = fs::read("/etc/resolv.conf").unwrap();
    let names = fs::read("/etc/nsswitch.conf").unwrap();
    let links = Command::new("ip")
        .args(["-j", "link", "show"])
        .output()
        .unwrap()
        .stdout;
    assert!(namespace::private_dns().is_err());
    assert!(namespace::default_route("mosaic0").is_err());
    for mode in ["check", "kill"] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--ignored",
                "--exact",
                "linux_private_dns_and_no_escape",
                "--nocapture",
            ])
            .env("MOSAIC_DNS_FIXTURE", mode)
            .stdout(Stdio::piped());
        unsafe {
            command
                .pre_exec(|| linux::check(libc::unshare(libc::CLONE_NEWNET | libc::CLONE_NEWNS)));
        }
        let mut child = command.spawn().unwrap();
        if mode == "kill" {
            let mut output = BufReader::new(child.stdout.take().unwrap());
            let mut line = String::new();
            loop {
                assert!(
                    output.read_line(&mut line).unwrap() > 0,
                    "fixture failed before readiness"
                );
                if line.contains("resolver ready") {
                    break;
                }
                line.clear();
            }
            child.kill().unwrap();
        }
        let status = child.wait().unwrap();
        assert_eq!(status.success(), mode == "check");
        assert_eq!(fs::read("/etc/resolv.conf").unwrap(), resolver);
        assert_eq!(fs::read("/etc/nsswitch.conf").unwrap(), names);
        assert_eq!(
            Command::new("ip")
                .args(["-j", "link", "show"])
                .output()
                .unwrap()
                .stdout,
            links
        );
    }
}
