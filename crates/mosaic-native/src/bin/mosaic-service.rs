fn main() {
    #[cfg(target_os = "linux")]
    {
        let result = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map(|runtime| runtime.block_on(mosaic_native::service::serve()));
        if !matches!(result, Ok(Ok(()))) {
            eprintln!(
                "FAIL: native service stopped; retained protection requires explicit recovery"
            );
            std::process::exit(1);
        }
    }
    #[cfg(target_os = "windows")]
    {
        if mosaic_native::windows::serve().is_err() {
            std::process::exit(1);
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        eprintln!(
            "Use the installed Apple extension or Android VPN service on this operating system"
        );
        std::process::exit(2);
    }
}
