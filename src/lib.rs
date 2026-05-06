#![cfg_attr(not(feature = "std"), no_std)]

//! Canonical ABI contract for the Alani MVK.
//!
//! This crate is intentionally dependency-free. It owns syscall numbers,
//! ABI-safe `repr(C)` structures, status values, handle/capability types,
//! feature negotiation, and version discovery records consumed by kernel and
//! userspace crates.

pub mod errors;
pub mod handles;
pub mod syscall;
pub mod version;

pub use errors::{status_to_result, AbiError, AbiResult, AlaniStatus, ErrorsDescriptor};
pub use handles::{
    AuditHandle, CapabilityHandle, CapabilityRights, DeviceHandle, Handle, HandlesDescriptor,
    IntentHandle, ModelHandle, ObjectHandle, ObjectKind, SharedMemoryHandle, TaskHandle,
    CAP_ATTEST, CAP_AUDIT_APPEND, CAP_AUDIT_QUERY, CAP_AUDIT_VERIFY, CAP_CAPABILITY_ADMIN,
    CAP_COGNITION_INFER, CAP_COGNITION_MEMORY_WRITE, CAP_DEVICE_CALL, CAP_DEVICE_LIST,
    CAP_DEVICE_OPEN, CAP_MEMORY_MAP, CAP_MEMORY_SHARE, CAP_RANDOM, CAP_TASK_MANAGE, CAP_TASK_SPAWN,
    CAP_TRACE_CONTEXT, KNOWN_CAPABILITY_RIGHTS,
};
pub use syscall::{
    descriptor, descriptor_from_raw, AuditEvent, ExecutionContext, InferenceBudget, SysInfo,
    SyscallArgKind, SyscallDescriptor, SyscallFrame, SyscallGroup, SyscallModuleDescriptor,
    SyscallNumber, SyscallReturn, TraceContext, UserBuffer, DEFAULT_MAX_USER_BUFFER_LEN,
    INFERENCE_FLAG_CACHE_ALLOWED, INFERENCE_FLAG_DETERMINISTIC, INFERENCE_KNOWN_FLAGS,
    SYSCALL_CONTEXT_EARLY_BOOT, SYSCALL_CONTEXT_INTERRUPT, SYSCALL_CONTEXT_KNOWN_FLAGS,
    SYSCALL_CONTEXT_TASK, SYSCALL_TABLE, SYSCALL_TABLE_LEN, SYSCALL_TABLE_VERSION,
    TRACE_FLAG_DEBUG, TRACE_FLAG_SAMPLED, TRACE_KNOWN_FLAGS, USER_BUFFER_KNOWN_FLAGS,
    USER_BUFFER_PINNABLE, USER_BUFFER_READ, USER_BUFFER_WRITE,
};
pub use version::{
    AbiFeatureSet, AbiHeader, AbiVersion, VersionDescriptor, ABI_FEATURE_AUDIT_METADATA,
    ABI_FEATURE_CAPABILITY_HANDLES, ABI_FEATURE_INFERENCE_BUDGETS, ABI_FEATURE_SYSCALL_TABLE,
    ABI_FEATURE_TRACE_CONTEXT, ABI_FEATURE_USER_BUFFERS, ABI_KNOWN_FEATURES, ALANI_ABI_FEATURES,
    ALANI_ABI_MAJOR, ALANI_ABI_MINOR, ALANI_ABI_PATCH, ALANI_ABI_VERSION,
};

/// Repository name.
pub const REPOSITORY: &str = "alani-abi";

/// Crate version.
pub const VERSION: &str = "0.1.0";

/// Public module names exposed by this crate.
pub const MODULES: &[&str] = &["syscall", "handles", "errors", "version"];

/// Implementation maturity marker for generated repository metadata.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ComponentStatus {
    /// API is present as a draft skeleton.
    Draft,
    /// API is implemented enough for host-mode experimentation.
    Experimental,
    /// API is compatible and stable.
    Stable,
}

/// Stable component identity record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ComponentInfo {
    /// Repository name.
    pub repository: &'static str,
    /// Crate version.
    pub version: &'static str,
    /// Current implementation status.
    pub status: ComponentStatus,
}

/// Returns stable component identity metadata.
pub const fn component_info() -> ComponentInfo {
    ComponentInfo {
        repository: REPOSITORY,
        version: VERSION,
        status: ComponentStatus::Experimental,
    }
}

/// Returns the repository name.
pub const fn repository_name() -> &'static str {
    REPOSITORY
}

/// Returns public module names.
pub fn module_names() -> &'static [&'static str] {
    MODULES
}

/// Compact root view of the ABI contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiCatalog {
    /// Current ABI structure version.
    pub abi_version: AbiVersion,
    /// Current syscall table version.
    pub syscall_table_version: AbiVersion,
    /// Supported feature bits.
    pub features: AbiFeatureSet,
    /// Number of syscall descriptors in the canonical table.
    pub syscall_count: u32,
    /// Maximum user buffer length accepted by ABI helpers.
    pub max_user_buffer_len: u64,
}

impl AbiCatalog {
    /// Current ABI catalog.
    pub const CURRENT: Self = Self {
        abi_version: ALANI_ABI_VERSION,
        syscall_table_version: SYSCALL_TABLE_VERSION,
        features: AbiFeatureSet(ALANI_ABI_FEATURES),
        syscall_count: SYSCALL_TABLE_LEN as u32,
        max_user_buffer_len: DEFAULT_MAX_USER_BUFFER_LEN,
    };

    /// Returns the current ABI catalog.
    pub const fn current() -> Self {
        Self::CURRENT
    }

    /// Converts the catalog to the `sys_info` payload.
    pub const fn sys_info(self) -> SysInfo {
        SysInfo {
            size: core::mem::size_of::<SysInfo>() as u32,
            reserved: 0,
            abi_version: self.abi_version,
            syscall_table_version: self.syscall_table_version,
            syscall_count: self.syscall_count,
            max_user_buffer_len: self.max_user_buffer_len,
            feature_bits: self.features.bits(),
        }
    }

    /// Looks up a syscall descriptor from the catalog.
    pub fn syscall_descriptor(self, number: SyscallNumber) -> Option<&'static SyscallDescriptor> {
        let _ = self;
        descriptor(number)
    }

    /// Validates the root catalog record.
    pub const fn validate(self) -> AbiResult<()> {
        if self.syscall_count != SYSCALL_TABLE_LEN as u32 || self.max_user_buffer_len == 0 {
            return Err(AbiError::InvalidVersion);
        }
        match self.abi_version.validate() {
            Ok(()) => match self.syscall_table_version.validate() {
                Ok(()) => match AbiFeatureSet::from_bits(self.features.bits()) {
                    Ok(_) => Ok(()),
                    Err(error) => Err(error),
                },
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        }
    }
}

/// Current ABI catalog.
pub const ABI_CATALOG: AbiCatalog = AbiCatalog::CURRENT;

/// Returns the current ABI catalog.
pub const fn abi_catalog() -> AbiCatalog {
    AbiCatalog::CURRENT
}

/// Returns the current `sys_info` payload.
pub const fn sys_info() -> SysInfo {
    AbiCatalog::CURRENT.sys_info()
}
