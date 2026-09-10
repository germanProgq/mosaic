use crate::{
    profile::private_file,
    service::{self, Request, Service},
};
use anyhow::{Context, Result, ensure};
use mosaic_core::native::{State, Status};
use std::{
    ffi::OsString, os::windows::io::AsRawHandle, path::PathBuf, ptr::null_mut, time::Duration,
};
use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::Threading::*,
};

const PIPE: &str = r"\\.\pipe\Mosaic.Control";
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
fn known_folder(id: &windows_sys::core::GUID) -> Result<PathBuf> {
    let mut value = null_mut();
    ensure!(
        unsafe {
            windows_sys::Win32::UI::Shell::SHGetKnownFolderPath(id, 0, null_mut(), &mut value)
        } == 0,
        "Windows installation directory unavailable"
    );
    let mut length = 0;
    while unsafe { *value.add(length) } != 0 {
        length += 1;
    }
    let path = String::from_utf16(unsafe { std::slice::from_raw_parts(value, length) });
    unsafe {
        windows_sys::Win32::System::Com::CoTaskMemFree(value.cast());
    }
    Ok(PathBuf::from(path?))
}

pub(super) fn root() -> Result<PathBuf> {
    Ok(known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramData)?.join("Mosaic"))
}

fn require_installation() -> Result<()> {
    let expected =
        known_folder(&windows_sys::Win32::UI::Shell::FOLDERID_ProgramFilesX64)?.join("Mosaic");
    let executable = std::env::current_exe()?;
    ensure!(
        executable
            .parent()
            .context("installation directory unavailable")?
            .canonicalize()?
            == expected.canonicalize()?,
        "install the MSI in Program Files before starting the privileged component"
    );
    Ok(())
}

fn sid() -> Result<String> {
    let mut token = null_mut();
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "cannot inspect installation user"
    );
    let mut length = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length);
    }
    let mut bytes = vec![0u64; (length as usize).div_ceil(8)];
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            bytes.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    ensure!(result != 0, "cannot inspect installation user");
    let user = unsafe { &*(bytes.as_ptr().cast::<TOKEN_USER>()) };
    let mut value = null_mut();
    ensure!(
        unsafe { ConvertSidToStringSidW(user.User.Sid, &mut value) } != 0,
        "invalid installation user"
    );
    let mut count = 0;
    while unsafe { *value.add(count) } != 0 && count < 256 {
        count += 1;
    }
    let text = String::from_utf16(unsafe { std::slice::from_raw_parts(value, count) })?;
    unsafe {
        LocalFree(value.cast());
    }
    Ok(text)
}

fn security(owner: &str) -> Result<*mut std::ffi::c_void> {
    ensure!(
        owner.starts_with("S-1-")
            && owner.len() <= 184
            && owner
                .bytes()
                .all(|byte| byte == b'-' || byte == b'S' || byte.is_ascii_digit()),
        "invalid local owner identity"
    );
    let text = wide(&format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{owner})"));
    let mut descriptor = null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } != 0,
        "cannot restrict local service access"
    );
    Ok(descriptor)
}

pub async fn request(request: Request) -> Result<Status> {
    let mut pipe = ClientOptions::new()
        .open(PIPE)
        .context("Mosaic service unavailable or this user is not authorized")?;
    let mut pid = 0;
    ensure!(
        unsafe {
            windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId(
                pipe.as_raw_handle(),
                &mut pid,
            )
        } != 0,
        "cannot verify local service identity"
    );
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    ensure!(!process.is_null(), "cannot verify local service process");
    let mut name = vec![0u16; 32768];
    let mut length = name.len() as u32;
    let result = unsafe { QueryFullProcessImageNameW(process, 0, name.as_mut_ptr(), &mut length) };
    unsafe {
        CloseHandle(process);
    }
    ensure!(result != 0, "cannot verify local service executable");
    let executable = PathBuf::from(String::from_utf16(&name[..length as usize])?);
    let expected = std::env::current_exe()?
        .parent()
        .context("installed directory unavailable")?
        .join("mosaic-service.exe");
    ensure!(
        executable.canonicalize()? == expected.canonicalize()?,
        "unexpected local service executable"
    );
    service::write(&mut pipe, &serde_json::to_vec(&request)?).await?;
    let bytes = tokio::time::timeout(Duration::from_secs(30), service::read(&mut pipe)).await??;
    Ok(serde_json::from_slice(&bytes)?)
}

async fn listen(mut stop: tokio::sync::watch::Receiver<bool>) -> Result<()> {
    let root = root()?;
    let owner = std::fs::read_to_string(root.join("owner"))?;
    let descriptor = security(owner.trim())?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as _,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .in_buffer_size(196608)
        .out_buffer_size(4096);
    let first = unsafe {
        options.create_with_security_attributes_raw(
            PIPE,
            (&attributes as *const SECURITY_ATTRIBUTES)
                .cast_mut()
                .cast(),
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    let mut pipe = first?;
    let mut service = Service::new(&root);
    let _ = service.recover().await;
    loop {
        tokio::select! {
            _ = stop.changed() => return Ok(()),
            connected = pipe.connect() => connected?,
        }
        let descriptor = security(owner.trim())?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as _,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let next = unsafe {
            ServerOptions::new()
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    PIPE,
                    (&attributes as *const SECURITY_ATTRIBUTES)
                        .cast_mut()
                        .cast(),
                )
        };
        unsafe {
            LocalFree(descriptor);
        }
        let next = next?;
        let result = tokio::time::timeout(Duration::from_secs(5), service::read(&mut pipe)).await;
        let response = match result {
            Ok(Ok(bytes)) => match serde_json::from_slice::<Request>(&bytes) {
                Ok(request) => service.handle(request).await,
                Err(_) => Status::new(State::Failed, "Invalid local request"),
            },
            _ => Status::new(
                State::Failed,
                "Local request exceeded its limit or deadline",
            ),
        };
        let _ = tokio::time::timeout(
            Duration::from_secs(5),
            service::write(&mut pipe, &serde_json::to_vec(&response)?),
        )
        .await;
        pipe = next;
    }
}

define_windows_service!(service_entry, start);
pub fn serve() -> Result<()> {
    require_installation()?;
    service_dispatcher::start("Mosaic", service_entry)?;
    Ok(())
}

fn start(_: Vec<OsString>) {
    let (stop, stopping) = tokio::sync::watch::channel(false);
    let Ok(status) = service_control_handler::register("Mosaic", move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            stop.send_replace(true);
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    }) else {
        return;
    };
    let update = |state, code| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
        exit_code: ServiceExitCode::Win32(code),
        checkpoint: 0,
        wait_hint: Duration::ZERO,
        process_id: None,
    };
    if status
        .set_service_status(update(ServiceState::Running, 0))
        .is_err()
    {
        return;
    }
    let result = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map(|runtime| runtime.block_on(listen(stopping)));
    let _ = status.set_service_status(update(
        ServiceState::Stopped,
        if matches!(result, Ok(Ok(()))) { 0 } else { 1 },
    ));
}

fn command(name: &str, arguments: &[&std::ffi::OsStr]) -> Result<()> {
    let mut directory = [0u16; 32768];
    let length = unsafe {
        windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW(
            directory.as_mut_ptr(),
            directory.len() as _,
        )
    };
    ensure!(
        length > 0 && length < directory.len() as u32,
        "Windows system directory unavailable"
    );
    let system = PathBuf::from(String::from_utf16(&directory[..length as usize])?).join(name);
    let mut child = std::process::Command::new(system)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(status) = child.try_wait()? {
            ensure!(
                status.success(),
                "Windows service installation operation failed"
            );
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("Windows service operation timed out");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn installed_service() -> Result<Option<windows_service::service::Service>> {
    use windows_service::{
        service::ServiceAccess,
        service_manager::{ServiceManager, ServiceManagerAccess},
    };
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let service = match manager.open_service(
        "Mosaic",
        ServiceAccess::QUERY_CONFIG
            | ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::DELETE,
    ) {
        Ok(service) => service,
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let configuration = service.query_config()?;
    let expected = std::env::current_exe()?
        .parent()
        .context("installed directory unavailable")?
        .join("mosaic-service.exe");
    let configured = configuration.executable_path.to_string_lossy();
    ensure!(
        PathBuf::from(configured.trim_matches('"')).canonicalize()? == expected.canonicalize()?,
        "service ownership conflict; preserve the existing Windows service"
    );
    Ok(Some(service))
}

pub fn setup(owner: Option<&str>) -> Result<()> {
    require_installation()?;
    let root = root()?;
    let selected_owner = owner.map(str::to_owned).map_or_else(sid, Ok)?;
    if root.exists() {
        ensure!(
            std::fs::read_to_string(root.join("owner"))?.trim() == selected_owner,
            "installation owner differs; preserve existing state"
        );
        if let Some(service) = installed_service()? {
            if service.query_status()?.current_state == ServiceState::Stopped {
                service.start::<&str>(&[])?;
            }
            return Ok(());
        }
    } else {
        ensure!(
            installed_service()?.is_none(),
            "Windows service exists without owned installation state"
        );
        std::fs::create_dir(&root)?;
        command(
            "icacls.exe",
            &[
                root.as_os_str(),
                "/inheritance:r".as_ref(),
                "/grant:r".as_ref(),
                "*S-1-5-18:(OI)(CI)F".as_ref(),
                "*S-1-5-32-544:(OI)(CI)F".as_ref(),
            ],
        )?;
    }
    let owner = selected_owner;
    let descriptor = security(&owner)?;
    unsafe {
        LocalFree(descriptor);
    }
    if !root.join("owner").exists() {
        private_file(&root.join("owner"), owner.as_bytes())?;
    }
    let binary = std::env::current_exe()?
        .parent()
        .context("installed directory unavailable")?
        .join("mosaic-service.exe");
    ensure!(
        binary.is_file(),
        "installed native service executable unavailable"
    );
    let quoted = format!("\"{}\"", binary.to_string_lossy());
    command(
        "sc.exe",
        &[
            "create".as_ref(),
            "Mosaic".as_ref(),
            "binPath=".as_ref(),
            quoted.as_ref(),
            "start=".as_ref(),
            "auto".as_ref(),
            "depend=".as_ref(),
            "BFE".as_ref(),
        ],
    )?;
    command(
        "sc.exe",
        &[
            "failure".as_ref(),
            "Mosaic".as_ref(),
            "reset=".as_ref(),
            "86400".as_ref(),
            "actions=".as_ref(),
            "restart/1000/restart/2000/restart/8000".as_ref(),
        ],
    )?;
    command("sc.exe", &["start".as_ref(), "Mosaic".as_ref()])?;
    Ok(())
}

pub fn uninstall() -> Result<()> {
    require_installation()?;
    ensure!(
        !root()?.join("connected").exists(),
        "disconnect before removing the service"
    );
    if let Some(service) = installed_service()? {
        if service.query_status()?.current_state != ServiceState::Stopped {
            service.stop()?;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(15);
        while service.query_status()?.current_state != ServiceState::Stopped {
            ensure!(
                std::time::Instant::now() < deadline,
                "service stop is still pending; retry uninstall after it stops"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        service.delete()?;
    }
    for name in ["profile.mosaic", "owner"] {
        let path = root()?.join(name);
        if path.is_file() {
            std::fs::remove_file(path)?;
        }
    }
    std::fs::remove_dir(root()?)?;
    Ok(())
}

pub fn create_private_file(path: &std::path::Path) -> Result<std::fs::File> {
    use std::os::windows::{ffi::OsStrExt, io::FromRawHandle};
    use windows_sys::Win32::Storage::FileSystem::*;
    let owner = sid()?;
    let text = wide(&format!("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{owner})"));
    let mut descriptor = null_mut();
    ensure!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                1,
                &mut descriptor,
                null_mut(),
            )
        } != 0,
        "cannot protect private file"
    );
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as _,
        lpSecurityDescriptor: descriptor,
        bInheritHandle: 0,
    };
    let name: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    unsafe {
        LocalFree(descriptor);
    }
    ensure!(
        handle != INVALID_HANDLE_VALUE,
        "cannot create new private file"
    );
    Ok(unsafe { std::fs::File::from_raw_handle(handle) })
}
