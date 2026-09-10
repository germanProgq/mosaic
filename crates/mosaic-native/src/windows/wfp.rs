use anyhow::{Result, ensure};
use mosaic_core::config::ClientConfig;
use std::ptr::{null, null_mut};
use windows_sys::{
    Win32::{Foundation::*, NetworkManagement::WindowsFilteringPlatform::*},
    core::GUID,
};

const PROVIDER: GUID = GUID::from_u128(0x6d6f7361_6963_4471_a023_85017974c001);
const SUBLAYER: GUID = GUID::from_u128(0x6d6f7361_6963_4471_a023_85017974c002);
fn key(index: u128) -> GUID {
    GUID::from_u128(0x6d6f7361_6963_4471_a023_85017974d000 + index)
}

struct Engine(HANDLE);
impl Engine {
    fn open() -> Result<Self> {
        let mut handle = null_mut();
        check(unsafe { FwpmEngineOpen0(null(), 10, null(), null(), &mut handle) })?;
        Ok(Self(handle))
    }
}
impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.0);
        }
    }
}

fn check(code: u32) -> Result<()> {
    ensure!(code == 0, "Windows traffic protection operation failed");
    Ok(())
}
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn same(a: &GUID, b: &GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

fn snapshot_path() -> Result<std::path::PathBuf> {
    Ok(super::control::root()?.join("protection.json"))
}

fn guid(value: &GUID) -> String {
    format!(
        "{:08x}{:04x}{:04x}{:02x?}",
        value.data1, value.data2, value.data3, value.data4
    )
}

fn fingerprint(filter: &FWPM_FILTER0) -> Result<serde_json::Value> {
    ensure!(
        !filter.providerKey.is_null() && unsafe { same(&*filter.providerKey, &PROVIDER) },
        "Windows filter ownership conflict"
    );
    let mut conditions = Vec::new();
    for index in 0..filter.numFilterConditions as usize {
        let condition = unsafe { &*filter.filterCondition.add(index) };
        let value = &condition.conditionValue;
        let data = unsafe {
            match value.r#type {
                FWP_UINT8 => serde_json::json!(value.Anonymous.uint8),
                FWP_UINT16 => serde_json::json!(value.Anonymous.uint16),
                FWP_UINT32 => serde_json::json!(value.Anonymous.uint32),
                FWP_UINT64 => serde_json::json!(*value.Anonymous.uint64),
                FWP_BYTE_BLOB_TYPE => {
                    let blob = &*value.Anonymous.byteBlob;
                    ensure!(blob.size <= 65536, "filter data exceeds limit");
                    serde_json::json!(std::slice::from_raw_parts(blob.data, blob.size as usize))
                }
                _ => anyhow::bail!("unexpected filter condition"),
            }
        };
        conditions.push(serde_json::json!([
            guid(&condition.fieldKey),
            condition.matchType,
            value.r#type,
            data
        ]));
    }
    ensure!(filter.weight.r#type == FWP_UINT8, "filter priority changed");
    Ok(
        serde_json::json!({"layer":guid(&filter.layerKey), "sublayer":guid(&filter.subLayerKey), "flags":filter.flags, "action":filter.action.r#type, "weight":unsafe {filter.weight.Anonymous.uint8}, "conditions":conditions}),
    )
}

fn inventory(engine: &Engine) -> Result<serde_json::Value> {
    let mut entries = serde_json::Map::new();
    for index in 0..64 {
        let mut filter: *mut FWPM_FILTER0 = null_mut();
        let code = unsafe { FwpmFilterGetByKey0(engine.0, &key(index), &mut filter) };
        if code == FWP_E_FILTER_NOT_FOUND as u32 {
            continue;
        }
        check(code)?;
        let result = fingerprint(unsafe { &*filter });
        unsafe {
            FwpmFreeMemory0((&mut filter as *mut *mut FWPM_FILTER0).cast());
        }
        entries.insert(index.to_string(), result?);
    }
    Ok(entries.into())
}

fn verify_saved(engine: &Engine) -> Result<()> {
    let actual = inventory(engine)?;
    if actual.as_object().is_some_and(|entries| entries.is_empty()) {
        return Ok(());
    }
    let saved: serde_json::Value = serde_json::from_slice(&mosaic_core::config::read_bounded(
        &snapshot_path()?,
        131072,
        true,
    )?)?;
    ensure!(
        actual == saved,
        "Windows filters changed externally; existing protection is preserved"
    );
    Ok(())
}

fn save(engine: &Engine) -> Result<()> {
    use std::io::Write;
    let path = snapshot_path()?;
    let mut file = tempfile::NamedTempFile::new_in(path.parent().unwrap())?;
    file.write_all(&serde_json::to_vec(&inventory(engine)?)?)?;
    file.as_file().sync_all()?;
    file.persist(path)
        .map_err(|_| anyhow::anyhow!("cannot save filter ownership"))?;
    Ok(())
}

fn remove_filters(engine: &Engine) -> Result<()> {
    for index in 0..64 {
        let mut filter: *mut FWPM_FILTER0 = null_mut();
        let code = unsafe { FwpmFilterGetByKey0(engine.0, &key(index), &mut filter) };
        if code == FWP_E_FILTER_NOT_FOUND as u32 {
            continue;
        }
        check(code)?;
        let owned =
            unsafe { !(*filter).providerKey.is_null() && same(&*(*filter).providerKey, &PROVIDER) };
        unsafe {
            FwpmFreeMemory0((&mut filter as *mut *mut FWPM_FILTER0).cast());
        }
        ensure!(owned, "Windows filter ownership conflict");
        check(unsafe { FwpmFilterDeleteByKey0(engine.0, &key(index)) })?;
    }
    Ok(())
}

pub fn apply(config: &ClientConfig, luid: u64, recovering: bool) -> Result<usize> {
    let engine = Engine::open()?;
    check(unsafe { FwpmTransactionBegin0(engine.0, 0) })?;
    let work = || -> Result<usize> {
        let mut name = wide("Mosaic protection");
        let provider = FWPM_PROVIDER0 {
            providerKey: PROVIDER,
            displayData: FWPM_DISPLAY_DATA0 {
                name: name.as_mut_ptr(),
                description: null_mut(),
            },
            flags: FWPM_PROVIDER_FLAG_PERSISTENT,
            ..Default::default()
        };
        let code = unsafe { FwpmProviderAdd0(engine.0, &provider, null_mut()) };
        ensure!(
            code == 0 || recovering && code == FWP_E_ALREADY_EXISTS as u32,
            "Windows protection provider already exists without owned state"
        );
        let mut provider_key = PROVIDER;
        let sublayer = FWPM_SUBLAYER0 {
            subLayerKey: SUBLAYER,
            displayData: provider.displayData,
            flags: FWPM_SUBLAYER_FLAG_PERSISTENT as _,
            providerKey: &mut provider_key,
            weight: 0x8000,
            ..Default::default()
        };
        let code = unsafe { FwpmSubLayerAdd0(engine.0, &sublayer, null_mut()) };
        ensure!(
            code == 0 || recovering && code == FWP_E_ALREADY_EXISTS as u32,
            "Windows protection sublayer ownership conflict"
        );
        if recovering {
            verify_saved(&engine)?;
            remove_filters(&engine)?;
        }
        let mut app = null_mut();
        let path = std::env::current_exe()?;
        use std::os::windows::ffi::OsStrExt;
        let filename: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        check(unsafe { FwpmGetAppIdFromFileName0(filename.as_ptr(), &mut app) })?;
        struct App(*mut FWP_BYTE_BLOB);
        impl Drop for App {
            fn drop(&mut self) {
                unsafe {
                    FwpmFreeMemory0((&mut self.0 as *mut *mut FWP_BYTE_BLOB).cast());
                }
            }
        }
        let app = App(app);
        let mut index = 0;
        let layers = [
            (FWPM_LAYER_ALE_AUTH_CONNECT_V4, true, false),
            (FWPM_LAYER_ALE_AUTH_CONNECT_V6, true, true),
            (FWPM_LAYER_OUTBOUND_TRANSPORT_V4, false, false),
            (FWPM_LAYER_OUTBOUND_TRANSPORT_V6, false, true),
        ];
        for (layer, application, ipv6) in layers {
            for boot in [false, true] {
                if application && boot {
                    continue;
                }
                let flags = if boot {
                    FWPM_FILTER_FLAG_BOOTTIME
                } else {
                    FWPM_FILTER_FLAG_PERSISTENT
                };
                let mut add = |weight: u8,
                               permit: bool,
                               conditions: &mut [FWPM_FILTER_CONDITION0]|
                 -> Result<()> {
                    let filter = FWPM_FILTER0 {
                        filterKey: key(index),
                        displayData: provider.displayData,
                        flags,
                        providerKey: &mut provider_key,
                        layerKey: layer,
                        subLayerKey: SUBLAYER,
                        weight: FWP_VALUE0 {
                            r#type: FWP_UINT8,
                            Anonymous: FWP_VALUE0_0 { uint8: weight },
                        },
                        numFilterConditions: conditions.len() as _,
                        filterCondition: conditions.as_mut_ptr(),
                        action: FWPM_ACTION0 {
                            r#type: if permit {
                                FWP_ACTION_PERMIT
                            } else {
                                FWP_ACTION_BLOCK
                            },
                            ..Default::default()
                        },
                        ..Default::default()
                    };
                    check(unsafe { FwpmFilterAdd0(engine.0, &filter, null_mut(), null_mut()) })?;
                    index += 1;
                    Ok(())
                };
                let mut loopback = condition(
                    FWPM_CONDITION_FLAGS,
                    FWP_UINT32,
                    FWP_CONDITION_VALUE0_0 {
                        uint32: FWP_CONDITION_FLAG_IS_LOOPBACK,
                    },
                );
                loopback.matchType = FWP_MATCH_FLAGS_ALL_SET;
                add(100, true, &mut [loopback])?;
                if !ipv6 {
                    let mut interface = luid;
                    if luid != 0 {
                        add(
                            90,
                            true,
                            &mut [condition(
                                FWPM_CONDITION_IP_LOCAL_INTERFACE,
                                FWP_UINT64,
                                FWP_CONDITION_VALUE0_0 {
                                    uint64: &mut interface,
                                },
                            )],
                        )?;
                    }
                    let ip = match config.server.address.ip() {
                        std::net::IpAddr::V4(ip) => u32::from(ip),
                        _ => unreachable!(),
                    };
                    let mut relay = vec![
                        condition(
                            FWPM_CONDITION_IP_REMOTE_ADDRESS,
                            FWP_UINT32,
                            FWP_CONDITION_VALUE0_0 { uint32: ip },
                        ),
                        condition(
                            FWPM_CONDITION_IP_PROTOCOL,
                            FWP_UINT8,
                            FWP_CONDITION_VALUE0_0 { uint8: 17 },
                        ),
                        condition(
                            FWPM_CONDITION_IP_REMOTE_PORT,
                            FWP_UINT16,
                            FWP_CONDITION_VALUE0_0 {
                                uint16: config.server.address.port(),
                            },
                        ),
                    ];
                    if application {
                        relay.push(condition(
                            FWPM_CONDITION_ALE_APP_ID,
                            FWP_BYTE_BLOB_TYPE,
                            FWP_CONDITION_VALUE0_0 { byteBlob: app.0 },
                        ));
                    }
                    add(80, true, &mut relay)?;
                    add(
                        70,
                        true,
                        &mut [
                            condition(
                                FWPM_CONDITION_IP_PROTOCOL,
                                FWP_UINT8,
                                FWP_CONDITION_VALUE0_0 { uint8: 17 },
                            ),
                            condition(
                                FWPM_CONDITION_IP_LOCAL_PORT,
                                FWP_UINT16,
                                FWP_CONDITION_VALUE0_0 { uint16: 68 },
                            ),
                            condition(
                                FWPM_CONDITION_IP_REMOTE_PORT,
                                FWP_UINT16,
                                FWP_CONDITION_VALUE0_0 { uint16: 67 },
                            ),
                            condition(
                                FWPM_CONDITION_IP_REMOTE_ADDRESS,
                                FWP_UINT32,
                                FWP_CONDITION_VALUE0_0 { uint32: u32::MAX },
                            ),
                        ],
                    )?;
                }
                add(1, false, &mut [])?;
            }
        }
        Ok(index as usize)
    };
    match work() {
        Ok(count) => {
            check(unsafe { FwpmTransactionCommit0(engine.0) })?;
            save(&engine)?;
            Ok(count)
        }
        Err(error) => {
            unsafe {
                FwpmTransactionAbort0(engine.0);
            }
            Err(error)
        }
    }
}

fn condition(
    field: GUID,
    kind: FWP_DATA_TYPE,
    value: FWP_CONDITION_VALUE0_0,
) -> FWPM_FILTER_CONDITION0 {
    FWPM_FILTER_CONDITION0 {
        fieldKey: field,
        matchType: FWP_MATCH_EQUAL,
        conditionValue: FWP_CONDITION_VALUE0 {
            r#type: kind,
            Anonymous: value,
        },
    }
}

pub fn verify(count: usize) -> Result<()> {
    let engine = Engine::open()?;
    let actual = inventory(&engine)?;
    ensure!(
        count > 0
            && actual
                .as_object()
                .is_some_and(|entries| entries.len() == count),
        "Windows traffic protection disappeared"
    );
    verify_saved(&engine)
}

pub fn cleanup() -> Result<()> {
    let engine = Engine::open()?;
    check(unsafe { FwpmTransactionBegin0(engine.0, 0) })?;
    let result = (|| -> Result<()> {
        verify_saved(&engine)?;
        remove_filters(&engine)?;
        let code = unsafe { FwpmSubLayerDeleteByKey0(engine.0, &SUBLAYER) };
        ensure!(
            code == 0 || code == FWP_E_SUBLAYER_NOT_FOUND as u32,
            "Windows protection sublayer cleanup failed"
        );
        let code = unsafe { FwpmProviderDeleteByKey0(engine.0, &PROVIDER) };
        ensure!(
            code == 0 || code == FWP_E_PROVIDER_NOT_FOUND as u32,
            "Windows protection provider cleanup failed"
        );
        check(unsafe { FwpmTransactionCommit0(engine.0) })?;
        let path = snapshot_path()?;
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    })();
    if result.is_err() {
        unsafe {
            FwpmTransactionAbort0(engine.0);
        }
    }
    result
}
