mod control;
mod wfp;
use anyhow::{Context, Result, ensure};
pub use control::create_private_file as private_file;
pub use control::{request, serve, setup, uninstall};
use mosaic_core::{config::ClientConfig, native::Platform, pump::PacketIo};
use std::{
    net::{Ipv4Addr, UdpSocket},
    os::windows::io::AsRawSocket,
    ptr::null_mut,
    sync::{Arc, Mutex},
    time::Duration,
};
use windows_sys::{
    Win32::{
        Foundation::*,
        NetworkManagement::{IpHelper::*, Ndis::*},
        Networking::WinSock::*,
    },
    core::GUID,
};

const ADAPTER: u128 = 0x6d6f7361_6963_4471_a023_85017974a001;

fn check(code: u32) -> Result<()> {
    ensure!(code == 0, "Windows network operation failed");
    Ok(())
}
fn address(ip: Ipv4Addr) -> SOCKADDR_INET {
    let mut value = SOCKADDR_IN {
        sin_family: AF_INET,
        ..Default::default()
    };
    value.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
    SOCKADDR_INET { Ipv4: value }
}

pub struct Network {
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
    config: ClientConfig,
    recovering: bool,
    filters: Mutex<usize>,
    path: Mutex<(u32, u32)>,
    configured: Mutex<bool>,
}

impl Network {
    pub fn create(config: &ClientConfig, recovering: bool) -> Result<Self> {
        config.validate()?;
        config.check_credentials()?;
        ensure!(config.mode == "native_tun", "native configuration required");
        wfp::apply(config, 0, recovering)?;
        let dll = std::env::current_exe()?
            .parent()
            .context("installed directory unavailable")?
            .join("wintun.dll");
        let wintun = unsafe { wintun::load_from_path(dll) }
            .map_err(|_| anyhow::anyhow!("installed signed Wintun component unavailable"))?;
        let adapter = match wintun::Adapter::open(&wintun, "Mosaic") {
            Ok(adapter) => {
                ensure!(
                    recovering && adapter.get_guid() == ADAPTER,
                    "Mosaic adapter already exists without owned state"
                );
                adapter
            }
            Err(_) => wintun::Adapter::create(&wintun, "Mosaic", "Mosaic", Some(ADAPTER))
                .map_err(|_| anyhow::anyhow!("cannot create the native adapter"))?,
        };
        let filters = wfp::apply(config, unsafe { adapter.get_luid().Value }, true)?;
        let session = Arc::new(
            adapter
                .start_session(256 * 1024)
                .map_err(|_| anyhow::anyhow!("cannot start bounded tunnel packet access"))?,
        );
        Ok(Self {
            adapter,
            session,
            config: config.clone(),
            recovering,
            filters: Mutex::new(filters),
            path: Mutex::new((0, 0)),
            configured: Mutex::new(false),
        })
    }

    fn luid(&self) -> NET_LUID_LH {
        NET_LUID_LH {
            Value: unsafe { self.adapter.get_luid().Value },
        }
    }

    fn underlying(&self) -> Result<(u32, u32)> {
        let mut table: *mut MIB_IPFORWARD_TABLE2 = null_mut();
        check(unsafe { GetIpForwardTable2(AF_INET, &mut table) })?;
        let routes = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        let remote = match self.config.server.address.ip() {
            std::net::IpAddr::V4(ip) => u32::from(ip),
            _ => unreachable!(),
        };
        let mut best = None;
        for route in routes {
            if unsafe { route.InterfaceLuid.Value == self.luid().Value } || route.Loopback {
                continue;
            }
            let prefix = route.DestinationPrefix.PrefixLength;
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network =
                u32::from_be(unsafe { route.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr });
            if remote & mask != network & mask {
                continue;
            }
            let mut interface = MIB_IPINTERFACE_ROW::default();
            unsafe {
                InitializeIpInterfaceEntry(&mut interface);
            }
            interface.Family = AF_INET;
            interface.InterfaceLuid = route.InterfaceLuid;
            if unsafe { GetIpInterfaceEntry(&mut interface) } != 0 || !interface.Connected {
                continue;
            }
            let candidate = (
                32 - prefix,
                route.Metric.saturating_add(interface.Metric),
                route.InterfaceIndex,
                unsafe { route.NextHop.Ipv4.sin_addr.S_un.S_addr },
            );
            if best.is_none_or(|old| candidate < old) {
                best = Some(candidate);
            }
        }
        unsafe {
            FreeMibTable(table.cast());
        }
        let (_, _, index, gateway) =
            best.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NetworkUnreachable))?;
        Ok((index, gateway))
    }

    pub fn changed(&self) -> Result<bool> {
        Ok(self.underlying()? != *self.path.lock().unwrap())
    }

    fn route(&self, upper: bool) -> MIB_IPFORWARD_ROW2 {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe {
            InitializeIpForwardEntry(&mut row);
        }
        row.InterfaceLuid = self.luid();
        row.DestinationPrefix.Prefix = address(if upper {
            Ipv4Addr::new(128, 0, 0, 0)
        } else {
            Ipv4Addr::UNSPECIFIED
        });
        row.DestinationPrefix.PrefixLength = 1;
        row.NextHop = address(Ipv4Addr::UNSPECIFIED);
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.Metric = 0;
        row
    }

    pub fn recover_cleanup(config: &ClientConfig) -> Result<()> {
        let dll = std::env::current_exe()?
            .parent()
            .context("installed directory unavailable")?
            .join("wintun.dll");
        let wintun = unsafe { wintun::load_from_path(dll) }
            .map_err(|_| anyhow::anyhow!("native adapter component unavailable"))?;
        if let Ok(adapter) = wintun::Adapter::open(&wintun, "Mosaic") {
            ensure!(
                adapter.get_guid() == ADAPTER,
                "native adapter ownership conflict"
            );
            let network = Self::create(config, true)?;
            network.cleanup()?;
        } else {
            wfp::cleanup()?;
        }
        Ok(())
    }

    pub fn cleanup(&self) -> Result<()> {
        for upper in [false, true] {
            let mut row = self.route(upper);
            let code = unsafe { GetIpForwardEntry2(&mut row) };
            if code == ERROR_NOT_FOUND {
                continue;
            }
            check(code)?;
            ensure!(
                row.Protocol == MIB_IPPROTO_NETMGMT && row.Metric == 0,
                "Mosaic route changed externally; resolve ownership conflict before cleanup"
            );
            check(unsafe { DeleteIpForwardEntry2(&row) })?;
        }
        let mut dns = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            ..Default::default()
        };
        let mut empty = [0u16];
        dns.NameServer = empty.as_mut_ptr();
        check(unsafe { SetInterfaceDnsSettings(GUID::from_u128(ADAPTER), &dns) })?;
        wfp::cleanup()?;
        Ok(())
    }
}

impl PacketIo for Network {
    async fn receive(&self, bytes: &mut [u8]) -> Result<usize> {
        loop {
            if let Some(packet) = self
                .session
                .try_receive()
                .map_err(|_| anyhow::anyhow!("native adapter read failed"))?
            {
                let packet = packet.bytes();
                if packet.len() > bytes.len() {
                    continue;
                }
                bytes[..packet.len()].copy_from_slice(packet);
                return Ok(packet.len());
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    async fn send(&self, bytes: &[u8]) -> Result<()> {
        ensure!(bytes.len() <= 1100, "packet exceeds MTU");
        let mut packet = self
            .session
            .allocate_send_packet(bytes.len() as u16)
            .map_err(|_| anyhow::anyhow!("native adapter queue unavailable"))?;
        packet.bytes_mut().copy_from_slice(bytes);
        self.session.send_packet(packet);
        Ok(())
    }
}

impl Platform for Network {
    async fn protect(&self, config: &ClientConfig) -> Result<()> {
        let mut filters = self.filters.lock().unwrap();
        if *filters == 0 {
            *filters = wfp::apply(config, unsafe { self.luid().Value }, self.recovering)?;
        } else {
            wfp::verify(*filters)?;
        }
        Ok(())
    }

    async fn socket(&self, _: &ClientConfig) -> Result<UdpSocket> {
        let path = self.underlying()?;
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        let interface = path.0.to_be();
        ensure!(
            unsafe {
                setsockopt(
                    socket.as_raw_socket() as _,
                    IPPROTO_IP,
                    IP_UNICAST_IF,
                    (&interface as *const u32).cast(),
                    4,
                )
            } == 0,
            "cannot bind the relay socket to its underlying network"
        );
        socket.set_nonblocking(true)?;
        *self.path.lock().unwrap() = path;
        Ok(socket)
    }

    async fn configure(&self, config: &ClientConfig) -> Result<()> {
        if *self.configured.lock().unwrap() {
            return Ok(());
        }
        let mut unicast = MIB_UNICASTIPADDRESS_ROW::default();
        unsafe {
            InitializeUnicastIpAddressEntry(&mut unicast);
        }
        unicast.InterfaceLuid = self.luid();
        unicast.Address = address(mosaic_core::config::tunnel(
            config.tunnel.as_ref().unwrap(),
        )?);
        unicast.OnLinkPrefixLength = 30;
        unicast.DadState = IpDadStatePreferred;
        let code = unsafe { CreateUnicastIpAddressEntry(&unicast) };
        ensure!(
            code == 0 || code == ERROR_OBJECT_ALREADY_EXISTS,
            "cannot configure native tunnel address"
        );
        let mut interface = MIB_IPINTERFACE_ROW::default();
        unsafe {
            InitializeIpInterfaceEntry(&mut interface);
        }
        interface.Family = AF_INET;
        interface.InterfaceLuid = self.luid();
        check(unsafe { GetIpInterfaceEntry(&mut interface) })?;
        interface.NlMtu = 1100;
        interface.UseAutomaticMetric = false;
        interface.Metric = 0;
        check(unsafe { SetIpInterfaceEntry(&mut interface) })?;
        for upper in [false, true] {
            let code = unsafe { CreateIpForwardEntry2(&self.route(upper)) };
            ensure!(
                code == 0 || self.recovering && code == ERROR_OBJECT_ALREADY_EXISTS,
                "native route collision"
            );
        }
        let mut names: Vec<u16> = "1.1.1.1".encode_utf16().chain(Some(0)).collect();
        let dns = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            Flags: DNS_SETTING_NAMESERVER as u64,
            NameServer: names.as_mut_ptr(),
            ..Default::default()
        };
        check(unsafe { SetInterfaceDnsSettings(GUID::from_u128(ADAPTER), &dns) })?;
        *self.configured.lock().unwrap() = true;
        Ok(())
    }

    async fn verify(&self) -> Result<()> {
        wfp::verify(*self.filters.lock().unwrap())?;
        for upper in [false, true] {
            check(unsafe { GetIpForwardEntry2(&mut self.route(upper)) })?;
        }
        let mut dns = DNS_INTERFACE_SETTINGS {
            Version: DNS_INTERFACE_SETTINGS_VERSION1,
            ..Default::default()
        };
        check(unsafe { GetInterfaceDnsSettings(GUID::from_u128(ADAPTER), &mut dns) })?;
        let matches = if dns.NameServer.is_null() {
            false
        } else {
            let expected: Vec<u16> = "1.1.1.1".encode_utf16().chain(Some(0)).collect();
            expected
                .iter()
                .enumerate()
                .all(|(index, byte)| unsafe { *dns.NameServer.add(index) == *byte })
        };
        unsafe {
            FreeInterfaceDnsSettings(&mut dns);
        }
        ensure!(matches, "native tunnel DNS changed");
        Ok(())
    }

    async fn discard(&self) -> Result<()> {
        for _ in 0..256 {
            if self
                .session
                .try_receive()
                .map_err(|_| anyhow::anyhow!("native adapter unavailable"))?
                .is_none()
            {
                break;
            }
        }
        Ok(())
    }
}
