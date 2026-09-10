use anyhow::{Result, ensure};
use std::{os::windows::io::AsRawHandle, ptr::null_mut};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    System::Threading::*,
};

pub fn check(file: &std::fs::File) -> Result<()> {
    let mut owner = null_mut();
    let mut acl = null_mut();
    let mut descriptor = null_mut();
    ensure!(
        unsafe {
            GetSecurityInfo(
                file.as_raw_handle(),
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut acl,
                null_mut(),
                &mut descriptor,
            )
        } == 0,
        "cannot inspect private file access"
    );
    let result = inspect(owner, acl);
    unsafe {
        LocalFree(descriptor);
    }
    result
}

fn inspect(owner: PSID, acl: *mut ACL) -> Result<()> {
    ensure!(
        !owner.is_null() && !acl.is_null(),
        "private file has unrestricted access"
    );
    let mut token = null_mut();
    ensure!(
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } != 0,
        "cannot inspect private file owner"
    );
    let mut length = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut length);
    }
    let mut buffer = vec![0u64; (length as usize).div_ceil(8)];
    let read = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    };
    unsafe {
        CloseHandle(token);
    }
    ensure!(read != 0, "cannot inspect private file owner");
    let current = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    for index in 0..unsafe { (*acl).AceCount } as u32 {
        let mut ace = null_mut();
        ensure!(
            unsafe { GetAce(acl, index, &mut ace) } != 0,
            "invalid private file access entry"
        );
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType == 1 {
            continue;
        }
        ensure!(header.AceType == 0, "unsupported private file access entry");
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = (&allowed.SidStart as *const u32).cast_mut().cast();
        ensure!(
            unsafe {
                EqualSid(sid, owner) != 0
                    || EqualSid(sid, current.User.Sid) != 0
                    || IsWellKnownSid(sid, WinLocalSystemSid) != 0
                    || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) != 0
            },
            "private file permits another account; restrict its Windows security permissions"
        );
    }
    Ok(())
}
