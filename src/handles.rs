//! ABI-safe handle and capability types.
//!
//! Handles are plain integer wrappers. Capability handles carry a rights mask,
//! owner task, generation, and reserved field so stale or malformed handles can
//! be rejected before subsystem access.

use crate::errors::{AbiError, AbiResult};

/// Permission to spawn child tasks.
pub const CAP_TASK_SPAWN: u64 = 1 << 0;
/// Permission to manage task lifecycle.
pub const CAP_TASK_MANAGE: u64 = 1 << 1;
/// Permission to map or unmap memory.
pub const CAP_MEMORY_MAP: u64 = 1 << 2;
/// Permission to share or seal memory handles.
pub const CAP_MEMORY_SHARE: u64 = 1 << 3;
/// Permission to list devices.
pub const CAP_DEVICE_LIST: u64 = 1 << 4;
/// Permission to open devices.
pub const CAP_DEVICE_OPEN: u64 = 1 << 5;
/// Permission to call devices.
pub const CAP_DEVICE_CALL: u64 = 1 << 6;
/// Permission to invoke cognition inference.
pub const CAP_COGNITION_INFER: u64 = 1 << 7;
/// Permission to write cognition memory.
pub const CAP_COGNITION_MEMORY_WRITE: u64 = 1 << 8;
/// Permission to derive or revoke capability handles.
pub const CAP_CAPABILITY_ADMIN: u64 = 1 << 9;
/// Permission to request attestation material.
pub const CAP_ATTEST: u64 = 1 << 10;
/// Permission to request random bytes.
pub const CAP_RANDOM: u64 = 1 << 11;
/// Permission to append audit records.
pub const CAP_AUDIT_APPEND: u64 = 1 << 12;
/// Permission to query audit records.
pub const CAP_AUDIT_QUERY: u64 = 1 << 13;
/// Permission to verify audit evidence.
pub const CAP_AUDIT_VERIFY: u64 = 1 << 14;
/// Permission to emit trace context updates.
pub const CAP_TRACE_CONTEXT: u64 = 1 << 15;

/// All capability bits known by this ABI version.
pub const KNOWN_CAPABILITY_RIGHTS: u64 = CAP_TASK_SPAWN
    | CAP_TASK_MANAGE
    | CAP_MEMORY_MAP
    | CAP_MEMORY_SHARE
    | CAP_DEVICE_LIST
    | CAP_DEVICE_OPEN
    | CAP_DEVICE_CALL
    | CAP_COGNITION_INFER
    | CAP_COGNITION_MEMORY_WRITE
    | CAP_CAPABILITY_ADMIN
    | CAP_ATTEST
    | CAP_RANDOM
    | CAP_AUDIT_APPEND
    | CAP_AUDIT_QUERY
    | CAP_AUDIT_VERIFY
    | CAP_TRACE_CONTEXT;

/// Generic kernel object handle.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Handle(pub u64);

impl Handle {
    /// Invalid handle value.
    pub const INVALID: Self = Self(0);

    /// Creates a handle from a raw value.
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    /// Returns the raw handle value.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Returns `true` when the handle is nonzero.
    pub const fn is_valid(self) -> bool {
        self.0 != 0
    }

    /// Validates the handle.
    pub const fn validate(self) -> AbiResult<()> {
        if self.is_valid() {
            Ok(())
        } else {
            Err(AbiError::InvalidHandle)
        }
    }
}

/// Task handle returned by task syscalls.
pub type TaskHandle = Handle;
/// Device handle returned by device syscalls.
pub type DeviceHandle = Handle;
/// Model handle returned by model syscalls.
pub type ModelHandle = Handle;
/// Shared-memory handle returned by memory syscalls.
pub type SharedMemoryHandle = Handle;
/// Intent handle used by future cognition flows.
pub type IntentHandle = Handle;
/// Audit handle used by audit query flows.
pub type AuditHandle = Handle;

/// Kernel object kind encoded in capability provenance.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectKind {
    /// No object kind.
    None = 0,
    /// Task object.
    Task = 1,
    /// Memory object.
    Memory = 2,
    /// Device object.
    Device = 3,
    /// Cognitive model object.
    Model = 4,
    /// Capability object.
    Capability = 5,
    /// Audit object.
    Audit = 6,
}

impl ObjectKind {
    /// Converts a raw value to a known object kind.
    pub const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            0 => Some(Self::None),
            1 => Some(Self::Task),
            2 => Some(Self::Memory),
            3 => Some(Self::Device),
            4 => Some(Self::Model),
            5 => Some(Self::Capability),
            6 => Some(Self::Audit),
            _ => None,
        }
    }
}

/// Capability rights bitset.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityRights(pub u64);

impl CapabilityRights {
    /// Empty rights set.
    pub const EMPTY: Self = Self(0);
    /// All known rights.
    pub const ALL: Self = Self(KNOWN_CAPABILITY_RIGHTS);

    /// Creates a rights set from raw bits.
    pub const fn from_bits(bits: u64) -> AbiResult<Self> {
        if bits & !KNOWN_CAPABILITY_RIGHTS != 0 {
            Err(AbiError::ReservedBits)
        } else {
            Ok(Self(bits))
        }
    }

    /// Returns raw rights bits.
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Returns `true` when all required rights are present.
    pub const fn contains(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Returns the union of two rights sets.
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Capability handle represented by the kernel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityHandle {
    /// Kernel-assigned handle identifier. Zero is invalid.
    pub id: u64,
    /// Rights bitmask attached to the handle.
    pub rights: u64,
    /// Owning task identifier.
    pub owner_task: u64,
    /// Handle generation to prevent stale reuse.
    pub generation: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl CapabilityHandle {
    /// Invalid zero capability handle.
    pub const INVALID: Self = Self {
        id: 0,
        rights: 0,
        owner_task: 0,
        generation: 0,
        reserved: 0,
    };

    /// Creates a capability handle.
    pub const fn new(id: u64, rights: CapabilityRights, owner_task: u64, generation: u32) -> Self {
        Self {
            id,
            rights: rights.bits(),
            owner_task,
            generation,
            reserved: 0,
        }
    }

    /// Returns `true` when the handle has a nonzero id and owner.
    pub const fn is_valid(self) -> bool {
        self.id != 0 && self.owner_task != 0 && self.generation != 0
    }

    /// Returns the rights set if no unknown bits are present.
    pub const fn rights(self) -> AbiResult<CapabilityRights> {
        CapabilityRights::from_bits(self.rights)
    }

    /// Validates nonzero identity, known rights, and reserved fields.
    pub const fn validate(self) -> AbiResult<()> {
        if self.reserved != 0 {
            return Err(AbiError::ReservedBits);
        }
        if !self.is_valid() {
            return Err(AbiError::InvalidHandle);
        }
        match self.rights() {
            Ok(_) => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// Checks that the handle contains all required rights.
    pub const fn require(self, required: CapabilityRights) -> AbiResult<()> {
        match self.validate() {
            Ok(()) => match self.rights() {
                Ok(rights) => {
                    if rights.contains(required) {
                        Ok(())
                    } else {
                        Err(AbiError::MissingCapability)
                    }
                }
                Err(error) => Err(error),
            },
            Err(error) => Err(error),
        }
    }
}

/// Typed handle descriptor used by table queries and diagnostics.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObjectHandle {
    /// Generic handle value.
    pub handle: Handle,
    /// Object kind.
    pub kind: ObjectKind,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl ObjectHandle {
    /// Creates a typed object handle.
    pub const fn new(handle: Handle, kind: ObjectKind) -> Self {
        Self {
            handle,
            kind,
            reserved: 0,
        }
    }

    /// Validates handle and reserved fields.
    pub const fn validate(self) -> AbiResult<()> {
        if self.reserved != 0 || matches!(self.kind, ObjectKind::None) {
            return Err(AbiError::ReservedBits);
        }
        self.handle.validate()
    }
}

/// Descriptor for the handles component itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandlesDescriptor<'a> {
    /// Component name.
    pub name: &'a str,
    /// Component version marker.
    pub version: u32,
}

impl<'a> HandlesDescriptor<'a> {
    /// Creates a handles component descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
