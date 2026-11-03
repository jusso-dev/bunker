//! Windows owner-only enforcement for host credential and state paths.
//!
//! The Unix rules (mode 0700/0600, owned by the effective user, no links) map to ACLs:
//! the owner must be a trusted SID, the DACL must exist and every allow entry must name a
//! trusted SID, directories must carry a protected DACL (no inherited entries), and
//! reparse points (symlinks, junctions) and multiply linked files are rejected.
//! Trusted SIDs are the process token user, the token default owner (BUILTIN\Administrators
//! for elevated administrators) and LocalSystem.
use anyhow::{ensure, Context, Result};
use std::{
    fs::File,
    io,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle, OwnedHandle},
    },
    path::{Path, PathBuf},
    ptr::{null, null_mut},
};
use windows_sys::Win32::{
    Foundation::{
        LocalFree, ERROR_ALREADY_EXISTS, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE,
        INVALID_HANDLE_VALUE,
    },
    Security::{
        AddAccessAllowedAceEx, CreateWellKnownSid, EqualSid, GetLengthSid,
        GetSecurityDescriptorControl, GetTokenInformation, InitializeAcl,
        InitializeSecurityDescriptor, IsValidSid, SetSecurityDescriptorControl,
        SetSecurityDescriptorDacl, TokenOwner, TokenUser, WinBuiltinAdministratorsSid,
        WinLocalSystemSid, ACCESS_ALLOWED_ACE, ACL, ACL_REVISION, CONTAINER_INHERIT_ACE,
        DACL_SECURITY_INFORMATION, INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE,
        OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
        SECURITY_DESCRIPTOR, SECURITY_MAX_SID_SIZE, SE_DACL_PROTECTED, TOKEN_OWNER, TOKEN_QUERY,
        TOKEN_USER, WELL_KNOWN_SID_TYPE,
    },
    Storage::FileSystem::{
        CreateDirectoryW, CreateFileW, GetFileInformationByHandle, GetFileType,
        BY_HANDLE_FILE_INFORMATION, DELETE, FILE_ALL_ACCESS, FILE_ATTRIBUTE_DIRECTORY,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_DELETE_CHILD, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, FILE_TYPE_DISK, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        Memory::LocalSize,
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

// winnt.h values; importing System_SystemServices for three constants is not worth it.
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const GENERIC_ALL: u32 = 0x10000000;
const GENERIC_WRITE: u32 = 0x40000000;

/// A SID copied into owned, DWORD-aligned storage.
struct Sid(Vec<u32>);
impl Sid {
    /// # Safety
    /// `sid` must point to a SID that stays valid for the duration of the call.
    unsafe fn copy(sid: PSID) -> Result<Self> {
        ensure!(
            !sid.is_null() && unsafe { IsValidSid(sid) } != 0,
            "invalid security identifier"
        );
        let len = unsafe { GetLengthSid(sid) } as usize;
        let mut buffer = vec![0u32; len.div_ceil(4)];
        unsafe { std::ptr::copy_nonoverlapping(sid as *const u8, buffer.as_mut_ptr().cast(), len) };
        Ok(Self(buffer))
    }
    fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Result<Self> {
        let mut buffer = vec![0u32; SECURITY_MAX_SID_SIZE.div_ceil(4) as usize];
        let mut size = SECURITY_MAX_SID_SIZE;
        if unsafe { CreateWellKnownSid(kind, null_mut(), buffer.as_mut_ptr().cast(), &mut size) }
            == 0
        {
            return Err(io::Error::last_os_error()).context("create well-known SID");
        }
        Ok(Self(buffer))
    }
    fn as_psid(&self) -> PSID {
        self.0.as_ptr() as PSID
    }
    fn trusted_installer() -> Result<Self> {
        use windows_sys::Win32::Security::Authorization::ConvertStringSidToSidW;
        // The Windows Modules Installer service owns standard system ancestors.
        let mut raw = null_mut();
        if unsafe {
            ConvertStringSidToSidW(
                windows_sys::w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"),
                &mut raw,
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("create TrustedInstaller SID");
        }
        let sid = unsafe { Self::copy(raw) };
        unsafe { LocalFree(raw) };
        sid
    }
    fn len(&self) -> u32 {
        unsafe { GetLengthSid(self.as_psid()) }
    }
}

/// SIDs allowed to own or be granted access to protected host state.
struct Trusted {
    user: Sid,
    owner: Sid,
    system: Sid,
}
impl Trusted {
    fn current() -> Result<Self> {
        let mut raw: HANDLE = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw) } == 0 {
            return Err(io::Error::last_os_error()).context("open process token");
        }
        let token = unsafe { OwnedHandle::from_raw_handle(raw) };
        let user = token_information(&token, TokenUser)?;
        let owner = token_information(&token, TokenOwner)?;
        // Both buffers start with a pointer into themselves and stay alive while copied.
        let user = unsafe { Sid::copy((*user.as_ptr().cast::<TOKEN_USER>()).User.Sid)? };
        let owner = unsafe { Sid::copy((*owner.as_ptr().cast::<TOKEN_OWNER>()).Owner)? };
        Ok(Self {
            user,
            owner,
            system: Sid::well_known(WinLocalSystemSid)?,
        })
    }
    fn contains(&self, sid: PSID) -> bool {
        !sid.is_null()
            && unsafe { IsValidSid(sid) } != 0
            && [&self.user, &self.owner, &self.system]
                .iter()
                .any(|trusted| unsafe { EqualSid(trusted.as_psid(), sid) } != 0)
    }
}
fn token_information(token: &OwnedHandle, class: i32) -> Result<Vec<u64>> {
    let handle = token.as_raw_handle() as HANDLE;
    let mut needed = 0u32;
    unsafe { GetTokenInformation(handle, class, null_mut(), 0, &mut needed) };
    let error = io::Error::last_os_error();
    if error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error).context("query process token");
    }
    // u64 storage keeps the embedded pointers aligned.
    let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
    if unsafe {
        GetTokenInformation(
            handle,
            class,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("query process token");
    }
    Ok(buffer)
}

/// Owner and DACL of an open object; the descriptor is freed on drop.
struct Security {
    descriptor: PSECURITY_DESCRIPTOR,
    owner: PSID,
    dacl: *mut ACL,
}
impl Security {
    /// GetSecurityInfo returns one LocalAlloc descriptor allocation. Bound every
    /// pointer and ACL/SID read by the allocation, not by attacker-controlled sizes.
    fn bytes_from(&self, pointer: *const u8, minimum: usize) -> Result<&[u8]> {
        let start = self.descriptor as usize;
        let length = unsafe { LocalSize(self.descriptor) };
        ensure!(
            length != 0,
            "cannot determine security descriptor allocation size"
        );
        let offset = (pointer as usize).checked_sub(start);
        let offset = offset
            .filter(|offset| *offset <= length)
            .context("security data is outside its descriptor")?;
        ensure!(minimum <= length - offset, "truncated security descriptor");
        Ok(unsafe { std::slice::from_raw_parts(pointer, length - offset) })
    }
    fn entries(&self) -> Result<Vec<crate::win_acl_parser::Ace<'_>>> {
        ensure!(
            !self.dacl.is_null(),
            "protected path has a NULL DACL granting everyone access"
        );
        crate::win_acl_parser::parse_acl(self.bytes_from(self.dacl.cast(), 8)?)
    }
    fn checked_owner(&self) -> Result<PSID> {
        let bytes = self.bytes_from(self.owner.cast(), 8)?;
        crate::win_acl_parser::sid_length(bytes)?;
        Ok(self.owner)
    }
}
impl Drop for Security {
    fn drop(&mut self) {
        if !self.descriptor.is_null() {
            unsafe { LocalFree(self.descriptor) };
        }
    }
}
fn security(handle: HANDLE) -> Result<Security> {
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    let mut security = Security {
        descriptor: null_mut(),
        owner: null_mut(),
        dacl: null_mut(),
    };
    let status = unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut security.owner,
            null_mut(),
            &mut security.dacl,
            null_mut(),
            &mut security.descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status as i32)).context("read file security");
    }
    Ok(security)
}

fn wide(path: &Path) -> Result<Vec<u16>> {
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    ensure!(!wide.contains(&0), "path contains a NUL character");
    wide.push(0);
    Ok(wide)
}
/// Open the final component itself, never a reparse target, with the given access.
fn open_no_follow(path: &Path, access: u32) -> Result<OwnedHandle> {
    let name = wide(path)?;
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            access,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error().into());
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}
fn information(handle: HANDLE) -> Result<BY_HANDLE_FILE_INFORMATION> {
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    if unsafe { GetFileInformationByHandle(handle, &mut info) } == 0 {
        return Err(io::Error::last_os_error()).context("read file information");
    }
    Ok(info)
}

fn check_handle(handle: HANDLE, directory: bool) -> Result<()> {
    let info = information(handle)?;
    ensure!(
        info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "protected path is a symlink, junction or other reparse point"
    );
    if directory {
        ensure!(
            info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            "protected path is not a directory"
        );
    } else {
        ensure!(
            unsafe { GetFileType(handle) } == FILE_TYPE_DISK
                && info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0,
            "protected path is not a regular file"
        );
        ensure!(
            info.nNumberOfLinks == 1,
            "protected file has more than one link"
        );
    }
    let trusted = Trusted::current()?;
    let security = security(handle)?;
    ensure!(
        trusted.contains(security.checked_owner()?),
        "protected path is not owned by the current user"
    );
    ensure!(
        !security.dacl.is_null(),
        "protected path has a NULL DACL granting everyone access"
    );
    if directory {
        let mut control = 0u16;
        let mut revision = 0u32;
        if unsafe { GetSecurityDescriptorControl(security.descriptor, &mut control, &mut revision) }
            == 0
        {
            return Err(io::Error::last_os_error()).context("read security descriptor control");
        }
        ensure!(
            control & SE_DACL_PROTECTED != 0,
            "protected directory inherits access from its parent"
        );
    }
    let mut user_inherits = false;
    for ace in security.entries()? {
        if ace.kind == ACCESS_ALLOWED_ACE_TYPE {
            let sid = ace.sid.as_ptr() as PSID;
            // Include inherit-only entries: they must not grant untrusted child access.
            ensure!(
                trusted.contains(sid),
                "protected path grants access to another user or group"
            );
            if ace.flags & INHERIT_ONLY_ACE as u8 == 0
                && ace.flags & (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
                    == (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE) as u8
                && ace.mask != 0
                && unsafe { EqualSid(trusted.user.as_psid(), sid) } != 0
            {
                user_inherits = true;
            }
        }
    }
    ensure!(
        !directory || user_inherits,
        "protected directory lacks an inheritable user allow entry"
    );
    Ok(())
}

/// Check each ancestor object from the volume root down, before resolving lower
/// components. Creation-only grants are safe; replacement and ACL-control grants
/// are allowed only for trusted state SIDs and Windows system administrators.
/// Root DELETE is immaterial; root child-deletion and ACL-control grants matter.
pub(crate) fn check_ancestors(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path.components().any(|c| matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )),
        "private state path must be normalized and absolute"
    );
    let trusted = Trusted::current()?;
    // Standard volume/profile ancestors grant Administrators full control even
    // for non-elevated users. Administrators already control these Windows paths.
    let administrators = Sid::well_known(WinBuiltinAdministratorsSid)?;
    let installer = Sid::trusted_installer()?;
    let ancestor_trusts = |sid: PSID| {
        trusted.contains(sid)
            || (unsafe { IsValidSid(sid) } != 0
                && [&administrators, &installer]
                    .iter()
                    .any(|trusted| unsafe { EqualSid(trusted.as_psid(), sid) } != 0))
    };
    let ancestors: Vec<_> = path.ancestors().skip(1).collect();
    for ancestor in ancestors.into_iter().rev() {
        let root = ancestor.parent().is_none();
        let handle = open_no_follow(ancestor, READ_CONTROL | FILE_READ_ATTRIBUTES)
            .with_context(|| format!("open private state ancestor {}", ancestor.display()))?;
        let raw = handle.as_raw_handle() as HANDLE;
        let info = information(raw)?;
        ensure!(
            info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0,
            "private state ancestor is not a directory"
        );
        ensure!(
            root || info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
            "private state ancestor is a symlink, junction or mount point"
        );
        let security = security(raw)?;
        // An owner can normally rewrite the DACL even without a WRITE_DAC ACE.
        ensure!(
            ancestor_trusts(security.checked_owner()?),
            "private state ancestor has an untrusted owner: {}",
            ancestor.display()
        );
        let dangerous = FILE_DELETE_CHILD
            | WRITE_DAC
            | WRITE_OWNER
            | GENERIC_ALL
            | GENERIC_WRITE
            | if root { 0 } else { DELETE };
        for ace in security.entries()? {
            if ace.kind == ACCESS_ALLOWED_ACE_TYPE
                && ace.flags & INHERIT_ONLY_ACE as u8 == 0
                && ace.mask & dangerous != 0
            {
                let sid = ace.sid.as_ptr() as PSID;
                ensure!(ancestor_trusts(sid),
                    "private state ancestor grants replacement or ACL control to another user or group: {}",
                    ancestor.display());
            }
        }
    }
    Ok(())
}

/// Validate an open file: regular, one link, trusted owner, trusted-only DACL.
pub(crate) fn check_file(file: &File) -> Result<()> {
    check_handle(file.as_raw_handle() as HANDLE, false)
}
/// Validate a path without following a final reparse point.
pub(crate) fn check_path(path: &Path, directory: bool) -> Result<()> {
    let handle = open_no_follow(path, READ_CONTROL | FILE_READ_ATTRIBUTES)?;
    check_handle(handle.as_raw_handle() as HANDLE, directory)
}

/// Create `path` with a protected DACL granting full control only to the current user and
/// SYSTEM, inherited by children. Returns false when the name already exists (unchanged).
pub(crate) fn create_private_directory(path: &Path) -> Result<bool> {
    let trusted = Trusted::current()?;
    let mut acl = protected_acl(&[&trusted.user, &trusted.system])?;
    let mut descriptor: SECURITY_DESCRIPTOR = unsafe { std::mem::zeroed() };
    let descriptor_ptr: PSECURITY_DESCRIPTOR = (&mut descriptor as *mut SECURITY_DESCRIPTOR).cast();
    unsafe {
        if InitializeSecurityDescriptor(descriptor_ptr, SECURITY_DESCRIPTOR_REVISION) == 0
            || SetSecurityDescriptorDacl(descriptor_ptr, 1, acl.as_mut_ptr().cast(), 0) == 0
            || SetSecurityDescriptorControl(descriptor_ptr, SE_DACL_PROTECTED, SE_DACL_PROTECTED)
                == 0
        {
            return Err(io::Error::last_os_error()).context("build private directory security");
        }
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor_ptr,
        bInheritHandle: 0,
    };
    let name = wide(path)?;
    // The DACL is applied atomically at creation, so no window exposes inherited access.
    if unsafe { CreateDirectoryW(name.as_ptr(), &attributes) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_ALREADY_EXISTS as i32) {
            return Ok(false);
        }
        return Err(error.into());
    }
    Ok(true)
}
/// A DACL granting full control, inherited by files and subdirectories, to `sids`.
fn protected_acl(sids: &[&Sid]) -> Result<Vec<u32>> {
    let header = std::mem::size_of::<ACL>() as u32;
    // Each entry is ACCESS_ALLOWED_ACE minus its placeholder SidStart plus the SID.
    let entry = (std::mem::size_of::<ACCESS_ALLOWED_ACE>() - std::mem::size_of::<u32>()) as u32;
    let size = header + sids.iter().map(|sid| entry + sid.len()).sum::<u32>();
    let mut acl = vec![0u32; size.div_ceil(4) as usize];
    let pointer: *mut ACL = acl.as_mut_ptr().cast();
    if unsafe { InitializeAcl(pointer, size, ACL_REVISION) } == 0 {
        return Err(io::Error::last_os_error()).context("initialize ACL");
    }
    for sid in sids {
        if unsafe {
            AddAccessAllowedAceEx(
                pointer,
                ACL_REVISION,
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
                FILE_ALL_ACCESS,
                sid.as_psid(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("add access control entry");
        }
    }
    Ok(acl)
}

/// Volume serial number and file index of a directory, rejecting reparse points.
pub(crate) fn directory_identity(path: &Path) -> Result<(u64, u64)> {
    let handle = open_no_follow(path, FILE_READ_ATTRIBUTES)?;
    let info = information(handle.as_raw_handle() as HANDLE)?;
    ensure!(
        info.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0
            && info.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT == 0,
        "restore destination changed"
    );
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
    ))
}

/// Whether `path` names the same location as `canonical` (a `canonicalize` result).
/// Verbatim `\\?\` prefixes are ignored for drive and UNC paths and case is folded, so any
/// remaining difference is rejected as an alias. Ancestor reparse checks, rather
/// than this string comparison, establish the absence of junctions/symlinks.
pub(crate) fn same_path(path: &Path, canonical: &Path) -> bool {
    match (comparable(path), comparable(canonical)) {
        (Some(a), Some(b)) => a == b,
        _ => path == canonical,
    }
}
/// Conservative Windows overlap comparison, including prospective final names.
pub(crate) fn overlaps(a: &Path, b: &Path) -> bool {
    match (comparable(a), comparable(b)) {
        (Some(a), Some(b)) => a.starts_with(&b) || b.starts_with(&a),
        _ => true, // Non-Unicode names cannot be safely compared by this policy.
    }
}
fn comparable(path: &Path) -> Option<PathBuf> {
    let text = path.to_str()?;
    let text = if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = text
        .strip_prefix(r"\\?\")
        .filter(|rest| rest.as_bytes().get(1) == Some(&b':'))
    {
        rest.to_owned()
    } else {
        text.to_owned()
    };
    Some(PathBuf::from(text.to_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use windows_sys::Win32::Security::{
        Authorization::{SetSecurityInfo, SE_FILE_OBJECT},
        WinWorldSid, PROTECTED_DACL_SECURITY_INFORMATION,
    };
    use windows_sys::Win32::Storage::FileSystem::WRITE_DAC;

    fn private(root: &Path) -> PathBuf {
        let dir = root.join("private");
        assert!(create_private_directory(&dir).unwrap());
        dir
    }
    fn set_protected_dacl(path: &Path, sids: &[&Sid]) {
        let acl = protected_acl(sids).unwrap();
        install_dacl(path, &acl);
    }
    fn install_dacl(path: &Path, acl: &[u32]) {
        let handle = open_no_follow(path, WRITE_DAC | READ_CONTROL).unwrap();
        let status = unsafe {
            SetSecurityInfo(
                handle.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                acl.as_ptr().cast(),
                null(),
            )
        };
        assert_eq!(status, ERROR_SUCCESS);
    }

    fn custom_acl(path: &Path, user_flags: u32, extra: Option<(&Sid, u32, u32)>) {
        let trusted = Trusted::current().unwrap();
        let mut acl = vec![0u32; 256];
        let pointer = acl.as_mut_ptr().cast();
        assert_ne!(unsafe { InitializeAcl(pointer, 1024, ACL_REVISION) }, 0);
        assert_ne!(
            unsafe {
                AddAccessAllowedAceEx(
                    pointer,
                    ACL_REVISION,
                    user_flags,
                    FILE_ALL_ACCESS,
                    trusted.user.as_psid(),
                )
            },
            0
        );
        if let Some((sid, mask, flags)) = extra {
            assert_ne!(
                unsafe { AddAccessAllowedAceEx(pointer, ACL_REVISION, flags, mask, sid.as_psid()) },
                0
            );
        }
        install_dacl(path, &acl);
    }

    #[test]
    fn non_inheritable_owner_only_directory_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let dir = private(temp.path());
        custom_acl(&dir, 0, None);
        let error = check_path(&dir, true).unwrap_err();
        assert!(error.to_string().contains("inheritable user allow"));
        custom_acl(
            &dir,
            OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
            None,
        );
        assert!(check_path(&dir, true).is_err());
        // No cleanup: the inherit-only ACL removed this user's effective access,
        // so restoring it can be denied; the temporary directory is disposable.
    }

    #[test]
    fn untrusted_ancestor_replacement_rights_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let ancestor = private(temp.path());
        let everyone = Sid::well_known(WinWorldSid).unwrap();
        for mask in [
            FILE_DELETE_CHILD,
            FILE_ALL_ACCESS,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
        ] {
            custom_acl(&ancestor, 0, Some((&everyone, mask, 0)));
            let error = check_ancestors(&ancestor.join("state")).unwrap_err();
            assert!(error.to_string().contains("replacement or ACL control"));
        }
        // Windows maps GENERIC_WRITE on a directory to add-file/add-subdirectory
        // rights, which cannot delete, rename or re-ACL it.
        custom_acl(&ancestor, 0, Some((&everyone, GENERIC_WRITE, 0)));
        check_ancestors(&ancestor.join("state")).unwrap();
    }

    #[test]
    fn standard_temp_ancestry_and_creation_only_grants_are_accepted() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().canonicalize().unwrap();
        check_ancestors(&base.join("state")).unwrap();
        let ancestor = private(&base);
        let everyone = Sid::well_known(WinWorldSid).unwrap();
        // Standard root/ProgramData creation-only grants do not allow replacement.
        custom_acl(&ancestor, 0, Some((&everyone, 0x6, 0)));
        check_ancestors(&ancestor.join("state")).unwrap();
        // Standard temp/root inherit-only Modify grants are not effective here.
        custom_acl(
            &ancestor,
            0,
            Some((
                &everyone,
                FILE_ALL_ACCESS,
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE,
            )),
        );
        check_ancestors(&ancestor.join("state")).unwrap();
    }

    #[test]
    fn protected_write_rejects_unsafe_new_file_before_publication() {
        let temp = tempfile::tempdir().unwrap();
        let dir = private(temp.path());
        let trusted = Trusted::current().unwrap();
        let everyone = Sid::well_known(WinWorldSid).unwrap();
        set_protected_dacl(&dir, &[&trusted.user, &everyone]);
        let capability =
            cap_std::fs::Dir::open_ambient_dir(&dir, cap_std::ambient_authority()).unwrap();
        assert!(
            crate::private_state::atomic_write(&capability, "secret", b"fixture", true).is_err()
        );
        assert!(!dir.join("secret").exists());
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
    }

    #[test]
    fn private_directory_and_child_files_validate() {
        let temp = tempfile::tempdir().unwrap();
        let dir = private(temp.path());
        check_path(&dir, true).unwrap();
        // An existing name is reported, never re-secured.
        assert!(!create_private_directory(&dir).unwrap());
        let file = dir.join("state.json");
        fs::write(&file, b"fixture").unwrap();
        check_file(&File::open(&file).unwrap()).unwrap();
        check_path(&file, false).unwrap();
        assert!(check_path(&file, true).is_err());
        assert!(check_path(&dir, false).is_err());
    }

    #[test]
    fn inherited_or_widened_directory_access_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let plain = temp.path().join("plain");
        fs::create_dir(&plain).unwrap();
        assert!(check_path(&plain, true).is_err());

        let dir = private(temp.path());
        let trusted = Trusted::current().unwrap();
        let everyone = Sid::well_known(WinWorldSid).unwrap();
        set_protected_dacl(&dir, &[&trusted.user, &trusted.system, &everyone]);
        let error = check_path(&dir, true).unwrap_err();
        assert!(error.to_string().contains("another user or group"));
        set_protected_dacl(&dir, &[&trusted.user, &trusted.system]);
        check_path(&dir, true).unwrap();
    }

    #[test]
    fn hard_linked_file_is_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let dir = private(temp.path());
        let file = dir.join("identity.json");
        fs::write(&file, b"fixture").unwrap();
        fs::hard_link(&file, dir.join("alias.json")).unwrap();
        let error = check_file(&File::open(&file).unwrap()).unwrap_err();
        assert!(error.to_string().contains("more than one link"));
        fs::remove_file(dir.join("alias.json")).unwrap();
        check_file(&File::open(&file).unwrap()).unwrap();
    }

    #[test]
    fn directory_identity_tracks_the_directory_not_its_name() {
        let temp = tempfile::tempdir().unwrap();
        let a = temp.path().join("a");
        let b = temp.path().join("b");
        fs::create_dir(&a).unwrap();
        fs::create_dir(&b).unwrap();
        let before = directory_identity(&a).unwrap();
        assert_eq!(directory_identity(&a).unwrap(), before);
        assert_ne!(directory_identity(&b).unwrap(), before);
        fs::remove_dir(&a).unwrap();
        fs::rename(&b, &a).unwrap();
        assert_ne!(directory_identity(&a).unwrap(), before);
        fs::write(temp.path().join("file"), b"x").unwrap();
        assert!(directory_identity(&temp.path().join("file")).is_err());
    }

    #[test]
    fn canonical_comparison_ignores_verbatim_prefix_and_case_only() {
        assert!(same_path(
            Path::new(r"C:\Data\Host"),
            Path::new(r"\\?\C:\data\host")
        ));
        assert!(same_path(
            Path::new(r"c:\data\host\"),
            Path::new(r"\\?\C:\Data\Host")
        ));
        assert!(same_path(
            Path::new(r"\\server\share\host"),
            Path::new(r"\\?\UNC\server\share\host")
        ));
        assert!(!same_path(
            Path::new(r"C:\Data\Alias"),
            Path::new(r"\\?\C:\Data\Host")
        ));
        assert!(!same_path(
            Path::new(r"C:\PROGRA~1\Host"),
            Path::new(r"\\?\C:\Program Files\Host")
        ));
    }

    #[test]
    fn overlap_comparison_folds_case_and_prospective_names() {
        assert!(overlaps(
            Path::new(r"C:\State\Future"),
            Path::new(r"c:\state\FUTURE")
        ));
        assert!(overlaps(
            Path::new(r"C:\State"),
            Path::new(r"\\?\c:\STATE\future")
        ));
        assert!(overlaps(
            Path::new(r"\\Server\Share\State"),
            Path::new(r"\\?\UNC\server\share\STATE\child")
        ));
        assert!(!overlaps(Path::new(r"C:\State"), Path::new(r"C:\State2")));
    }
}
