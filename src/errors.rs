//! Stable ABI status codes and validation errors.
//!
//! Kernel-facing code returns [`AlaniStatus`] across the ABI boundary. The
//! richer [`AbiError`] enum is for Rust-side validation helpers and always maps
//! back to one of the stable status values.

/// Stable status values returned across the kernel/user ABI boundary.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AlaniStatus {
    /// Operation completed successfully.
    Ok = 0,
    /// The caller provided malformed or out-of-range input.
    InvalidArgument = 1,
    /// The caller lacks authority for the requested operation.
    PermissionDenied = 2,
    /// The requested object does not exist.
    NotFound = 3,
    /// The subsystem is temporarily unable to make progress.
    Busy = 4,
    /// A declared deadline or budget was exceeded.
    DeadlineExceeded = 5,
    /// A kernel invariant failed or an internal subsystem fault occurred.
    Internal = 0xffff_ffff,
}

impl AlaniStatus {
    /// Converts a raw status value to a known ABI status.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::Ok),
            1 => Some(Self::InvalidArgument),
            2 => Some(Self::PermissionDenied),
            3 => Some(Self::NotFound),
            4 => Some(Self::Busy),
            5 => Some(Self::DeadlineExceeded),
            0xffff_ffff => Some(Self::Internal),
            _ => None,
        }
    }

    /// Returns the raw ABI status value.
    pub const fn raw(self) -> u32 {
        self as u32
    }

    /// Returns `true` when this status represents success.
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }

    /// Stable status label used by tests, traces, and future generated tables.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::InvalidArgument => "invalid_argument",
            Self::PermissionDenied => "permission_denied",
            Self::NotFound => "not_found",
            Self::Busy => "busy",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Internal => "internal",
        }
    }
}

/// Rust-side ABI validation error taxonomy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiError {
    /// A general argument validation check failed.
    InvalidArgument,
    /// ABI version fields or compatibility checks failed.
    InvalidVersion,
    /// A feature bit or flags field contained unknown bits.
    ReservedBits,
    /// A user buffer pointer, length, direction, or range was invalid.
    InvalidBuffer,
    /// A user buffer length exceeded the ABI ceiling.
    BufferTooLarge,
    /// A handle was zero, stale, or inconsistent with the target object.
    InvalidHandle,
    /// A capability handle did not include required rights.
    MissingCapability,
    /// A syscall number is not present in the canonical table.
    UnknownSyscall,
    /// A syscall was invoked from a forbidden execution context.
    InvalidContext,
    /// A trace context failed validation.
    InvalidTrace,
    /// A budget descriptor failed validation.
    InvalidBudget,
    /// The requested object does not exist.
    NotFound,
    /// A fixed-capacity table or subsystem cannot currently make progress.
    CapacityExceeded,
    /// A declared deadline was exceeded.
    DeadlineExceeded,
    /// The requested operation is not supported by this ABI version.
    Unsupported,
    /// An internal invariant failed.
    Internal,
}

impl AbiError {
    /// Maps this validation error to a stable ABI status value.
    pub const fn status(self) -> AlaniStatus {
        match self {
            Self::InvalidArgument
            | Self::InvalidVersion
            | Self::ReservedBits
            | Self::InvalidBuffer
            | Self::BufferTooLarge
            | Self::InvalidHandle
            | Self::UnknownSyscall
            | Self::InvalidContext
            | Self::InvalidTrace
            | Self::InvalidBudget => AlaniStatus::InvalidArgument,
            Self::MissingCapability => AlaniStatus::PermissionDenied,
            Self::NotFound => AlaniStatus::NotFound,
            Self::CapacityExceeded => AlaniStatus::Busy,
            Self::DeadlineExceeded => AlaniStatus::DeadlineExceeded,
            Self::Unsupported | Self::Internal => AlaniStatus::Internal,
        }
    }

    /// Short stable reason label.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid_argument",
            Self::InvalidVersion => "invalid_version",
            Self::ReservedBits => "reserved_bits",
            Self::InvalidBuffer => "invalid_buffer",
            Self::BufferTooLarge => "buffer_too_large",
            Self::InvalidHandle => "invalid_handle",
            Self::MissingCapability => "missing_capability",
            Self::UnknownSyscall => "unknown_syscall",
            Self::InvalidContext => "invalid_context",
            Self::InvalidTrace => "invalid_trace",
            Self::InvalidBudget => "invalid_budget",
            Self::NotFound => "not_found",
            Self::CapacityExceeded => "capacity_exceeded",
            Self::DeadlineExceeded => "deadline_exceeded",
            Self::Unsupported => "unsupported",
            Self::Internal => "internal",
        }
    }
}

impl From<AbiError> for AlaniStatus {
    fn from(error: AbiError) -> Self {
        error.status()
    }
}

/// Result alias used by ABI validation helpers.
pub type AbiResult<T> = Result<T, AbiError>;

/// Converts a kernel ABI status into an empty Rust result.
pub const fn status_to_result(status: AlaniStatus) -> AbiResult<()> {
    if status.is_ok() {
        Ok(())
    } else {
        Err(match status {
            AlaniStatus::Ok => AbiError::Internal,
            AlaniStatus::InvalidArgument => AbiError::InvalidArgument,
            AlaniStatus::PermissionDenied => AbiError::MissingCapability,
            AlaniStatus::NotFound => AbiError::NotFound,
            AlaniStatus::Busy => AbiError::CapacityExceeded,
            AlaniStatus::DeadlineExceeded => AbiError::DeadlineExceeded,
            AlaniStatus::Internal => AbiError::Internal,
        })
    }
}

/// Descriptor for the errors component itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ErrorsDescriptor<'a> {
    /// Component name.
    pub name: &'a str,
    /// Component version marker.
    pub version: u32,
}

impl<'a> ErrorsDescriptor<'a> {
    /// Creates an errors component descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
