//! ABI versioning and feature negotiation.
//!
//! Structure evolution uses explicit version, size, flags, and reserved fields.
//! Runtime code can discover the current ABI through `sys_info`.

use crate::errors::{AbiError, AbiResult};

/// Current ABI major version.
pub const ALANI_ABI_MAJOR: u16 = 0;
/// Current ABI minor version.
pub const ALANI_ABI_MINOR: u16 = 1;
/// Current ABI patch version.
pub const ALANI_ABI_PATCH: u16 = 0;

/// The ABI exposes syscall table metadata through `sys_info`.
pub const ABI_FEATURE_SYSCALL_TABLE: u64 = 1 << 0;
/// The ABI supports trace context propagation in syscall frames.
pub const ABI_FEATURE_TRACE_CONTEXT: u64 = 1 << 1;
/// The ABI supports capability handles and rights masks.
pub const ABI_FEATURE_CAPABILITY_HANDLES: u64 = 1 << 2;
/// The ABI supports bounded user-buffer descriptors.
pub const ABI_FEATURE_USER_BUFFERS: u64 = 1 << 3;
/// The ABI supports inference budget descriptors.
pub const ABI_FEATURE_INFERENCE_BUDGETS: u64 = 1 << 4;
/// The ABI supports audit syscall metadata.
pub const ABI_FEATURE_AUDIT_METADATA: u64 = 1 << 5;

/// All feature bits known by this ABI version.
pub const ABI_KNOWN_FEATURES: u64 = ABI_FEATURE_SYSCALL_TABLE
    | ABI_FEATURE_TRACE_CONTEXT
    | ABI_FEATURE_CAPABILITY_HANDLES
    | ABI_FEATURE_USER_BUFFERS
    | ABI_FEATURE_INFERENCE_BUDGETS
    | ABI_FEATURE_AUDIT_METADATA;

/// Current feature bitmap.
pub const ALANI_ABI_FEATURES: u64 = ABI_KNOWN_FEATURES;

/// Current draft ABI version exposed by `sys_info`.
pub const ALANI_ABI_VERSION: AbiVersion = AbiVersion {
    major: ALANI_ABI_MAJOR,
    minor: ALANI_ABI_MINOR,
    patch: ALANI_ABI_PATCH,
    flags: 0,
};

/// ABI version structure used for compatibility negotiation.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiVersion {
    /// Major version. Incompatible changes require a bump.
    pub major: u16,
    /// Minor version. Compatible additions require a bump.
    pub minor: u16,
    /// Patch version.
    pub patch: u16,
    /// Reserved version flags. Must be zero for this draft ABI.
    pub flags: u16,
}

impl AbiVersion {
    /// Creates an ABI version value.
    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
            flags: 0,
        }
    }

    /// Encodes the version in a register-friendly integer.
    pub const fn packed(self) -> u64 {
        ((self.major as u64) << 48)
            | ((self.minor as u64) << 32)
            | ((self.patch as u64) << 16)
            | self.flags as u64
    }

    /// Decodes a packed ABI version.
    pub const fn from_packed(value: u64) -> Self {
        Self {
            major: (value >> 48) as u16,
            minor: (value >> 32) as u16,
            patch: (value >> 16) as u16,
            flags: value as u16,
        }
    }

    /// Validates reserved fields.
    pub const fn validate(self) -> AbiResult<()> {
        if self.flags == 0 {
            Ok(())
        } else {
            Err(AbiError::ReservedBits)
        }
    }

    /// Returns `true` when `self` can consume structures from `other`.
    pub const fn is_compatible_with(self, other: Self) -> bool {
        self.major == other.major && self.minor >= other.minor
    }
}

/// Generic ABI structure header for extensible records.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiHeader {
    /// Structure size in bytes.
    pub size: u32,
    /// Structure flags. Unknown bits are rejected by structure-specific helpers.
    pub flags: u32,
    /// ABI version used by this structure.
    pub version: AbiVersion,
    /// Reserved for future evolution. Must be zero.
    pub reserved: u64,
}

impl AbiHeader {
    /// Creates a structure header.
    pub const fn new(size: u32, flags: u32, version: AbiVersion) -> Self {
        Self {
            size,
            flags,
            version,
            reserved: 0,
        }
    }

    /// Validates size, version, reserved fields, and known flags.
    pub const fn validate(self, min_size: u32, known_flags: u32) -> AbiResult<()> {
        if self.size < min_size {
            return Err(AbiError::InvalidVersion);
        }
        if self.reserved != 0 || self.flags & !known_flags != 0 {
            return Err(AbiError::ReservedBits);
        }
        self.version.validate()
    }
}

/// Feature set returned by compatibility negotiation.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiFeatureSet(pub u64);

impl AbiFeatureSet {
    /// Empty feature set.
    pub const EMPTY: Self = Self(0);
    /// All known features enabled.
    pub const ALL: Self = Self(ABI_KNOWN_FEATURES);

    /// Creates a feature set from raw bits.
    pub const fn from_bits(bits: u64) -> AbiResult<Self> {
        if bits & !ABI_KNOWN_FEATURES != 0 {
            Err(AbiError::ReservedBits)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns raw feature bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` when all requested features are present.
    pub const fn contains(self, requested: Self) -> bool {
        self.0 & requested.0 == requested.0
    }
}

/// Descriptor for the version component itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionDescriptor<'a> {
    /// Component name.
    pub name: &'a str,
    /// Component version marker.
    pub version: u32,
}

impl<'a> VersionDescriptor<'a> {
    /// Creates a version component descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
