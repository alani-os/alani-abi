//! Canonical syscall numbers, descriptors, and ABI-safe syscall structures.
//!
//! This module is the kernel/user syscall contract: numeric IDs, register
//! frames, return payloads, buffer descriptors, trace context, inference
//! budgets, and the static descriptor table used by conformance tests.

use core::mem::size_of;

use crate::errors::{status_to_result, AbiError, AbiResult, AlaniStatus};
use crate::handles::{
    CapabilityRights, CAP_ATTEST, CAP_AUDIT_APPEND, CAP_AUDIT_QUERY, CAP_AUDIT_VERIFY,
    CAP_CAPABILITY_ADMIN, CAP_COGNITION_INFER, CAP_COGNITION_MEMORY_WRITE, CAP_DEVICE_CALL,
    CAP_DEVICE_LIST, CAP_DEVICE_OPEN, CAP_MEMORY_MAP, CAP_MEMORY_SHARE, CAP_RANDOM,
    CAP_TASK_MANAGE, CAP_TASK_SPAWN, CAP_TRACE_CONTEXT,
};
use crate::version::{AbiVersion, ALANI_ABI_FEATURES, ALANI_ABI_VERSION};

/// Default maximum user buffer size used by ABI validation helpers.
pub const DEFAULT_MAX_USER_BUFFER_LEN: u64 = 16 * 1024 * 1024;

/// Buffer may be read by the kernel.
pub const USER_BUFFER_READ: u32 = 1 << 0;
/// Buffer may be written by the kernel.
pub const USER_BUFFER_WRITE: u32 = 1 << 1;
/// Buffer may be pinned by the kernel.
pub const USER_BUFFER_PINNABLE: u32 = 1 << 2;
/// Known user-buffer flag bits.
pub const USER_BUFFER_KNOWN_FLAGS: u32 =
    USER_BUFFER_READ | USER_BUFFER_WRITE | USER_BUFFER_PINNABLE;

/// Trace context is sampled.
pub const TRACE_FLAG_SAMPLED: u32 = 1 << 0;
/// Trace context is debug-visible.
pub const TRACE_FLAG_DEBUG: u32 = 1 << 1;
/// Known trace flags.
pub const TRACE_KNOWN_FLAGS: u32 = TRACE_FLAG_SAMPLED | TRACE_FLAG_DEBUG;

/// Inference should be deterministic when possible.
pub const INFERENCE_FLAG_DETERMINISTIC: u32 = 1 << 0;
/// Inference may use cached context.
pub const INFERENCE_FLAG_CACHE_ALLOWED: u32 = 1 << 1;
/// Known inference budget flags.
pub const INFERENCE_KNOWN_FLAGS: u32 = INFERENCE_FLAG_DETERMINISTIC | INFERENCE_FLAG_CACHE_ALLOWED;

/// Syscall may run during early boot.
pub const SYSCALL_CONTEXT_EARLY_BOOT: u32 = 1 << 0;
/// Syscall may run during normal task context.
pub const SYSCALL_CONTEXT_TASK: u32 = 1 << 1;
/// Syscall may run from interrupt context.
pub const SYSCALL_CONTEXT_INTERRUPT: u32 = 1 << 2;
/// Known syscall context bits.
pub const SYSCALL_CONTEXT_KNOWN_FLAGS: u32 =
    SYSCALL_CONTEXT_EARLY_BOOT | SYSCALL_CONTEXT_TASK | SYSCALL_CONTEXT_INTERRUPT;

/// Number of syscalls in the canonical table.
pub const SYSCALL_TABLE_LEN: usize = 30;

/// Syscall table version independent of crate version.
pub const SYSCALL_TABLE_VERSION: AbiVersion = AbiVersion {
    major: 0,
    minor: 1,
    patch: 0,
    flags: 0,
};

/// User buffer descriptor passed through syscall arguments.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UserBuffer {
    /// Userspace virtual address.
    pub ptr: u64,
    /// Buffer length in bytes.
    pub len: u64,
    /// Direction and pinning flags.
    pub flags: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl UserBuffer {
    /// Creates a descriptor from raw fields.
    pub const fn new(ptr: u64, len: u64, flags: u32) -> Self {
        Self {
            ptr,
            len,
            flags,
            reserved: 0,
        }
    }

    /// Creates and validates a descriptor from raw parts.
    pub const fn from_parts(ptr: u64, len: u64, flags: u32) -> AbiResult<Self> {
        let buffer = Self::new(ptr, len, flags);
        match buffer.validate() {
            Ok(()) => Ok(buffer),
            Err(error) => Err(error),
        }
    }

    /// Creates a kernel-readable buffer from a byte slice.
    pub fn read_only(bytes: &[u8]) -> AbiResult<Self> {
        Self::from_parts(
            bytes.as_ptr() as usize as u64,
            bytes.len() as u64,
            USER_BUFFER_READ,
        )
    }

    /// Creates a kernel-writable buffer from a mutable byte slice.
    pub fn write_only(bytes: &mut [u8]) -> AbiResult<Self> {
        Self::from_parts(
            bytes.as_mut_ptr() as usize as u64,
            bytes.len() as u64,
            USER_BUFFER_WRITE,
        )
    }

    /// Creates a read/write buffer from a mutable byte slice.
    pub fn read_write(bytes: &mut [u8]) -> AbiResult<Self> {
        Self::from_parts(
            bytes.as_mut_ptr() as usize as u64,
            bytes.len() as u64,
            USER_BUFFER_READ | USER_BUFFER_WRITE,
        )
    }

    /// Validates reserved fields, flags, null pointers, and length ceiling.
    pub const fn validate(self) -> AbiResult<()> {
        if self.reserved != 0 || self.flags & !USER_BUFFER_KNOWN_FLAGS != 0 {
            return Err(AbiError::ReservedBits);
        }
        if self.ptr == 0 || self.len == 0 {
            return Err(AbiError::InvalidBuffer);
        }
        if self.len > DEFAULT_MAX_USER_BUFFER_LEN {
            return Err(AbiError::BufferTooLarge);
        }
        Ok(())
    }

    /// Returns `true` when the buffer declares kernel-read access.
    pub const fn is_readable(self) -> bool {
        self.flags & USER_BUFFER_READ != 0
    }

    /// Returns `true` when the buffer declares kernel-write access.
    pub const fn is_writable(self) -> bool {
        self.flags & USER_BUFFER_WRITE != 0
    }

    /// Returns `true` when the buffer may be pinned by the kernel.
    pub const fn is_pinnable(self) -> bool {
        self.flags & USER_BUFFER_PINNABLE != 0
    }

    /// Packs pointer and length into syscall arguments.
    pub const fn ptr_len_args(self) -> [u64; 2] {
        [self.ptr, self.len]
    }
}

/// Cross-component trace context propagated through syscalls.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TraceContext {
    /// Stable trace identifier.
    pub trace_id: u64,
    /// Current span identifier.
    pub span_id: u64,
    /// Parent span identifier, or zero when absent.
    pub parent_span_id: u64,
    /// Trace flags.
    pub flags: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl TraceContext {
    /// Empty trace context.
    pub const EMPTY: Self = Self {
        trace_id: 0,
        span_id: 0,
        parent_span_id: 0,
        flags: 0,
        reserved: 0,
    };

    /// Returns an empty trace context.
    pub const fn empty() -> Self {
        Self::EMPTY
    }

    /// Creates a root span context.
    pub const fn root(trace_id: u64, span_id: u64) -> Self {
        Self {
            trace_id,
            span_id,
            parent_span_id: 0,
            flags: TRACE_FLAG_SAMPLED,
            reserved: 0,
        }
    }

    /// Creates a child span context.
    pub const fn child(self, span_id: u64) -> Self {
        Self {
            trace_id: self.trace_id,
            span_id,
            parent_span_id: self.span_id,
            flags: self.flags,
            reserved: 0,
        }
    }

    /// Returns `true` when trace and span identifiers are present.
    pub const fn is_valid_context(self) -> bool {
        self.trace_id != 0 && self.span_id != 0
    }

    /// Validates reserved fields and known flags.
    pub const fn validate(self) -> AbiResult<()> {
        if self.reserved != 0 || self.flags & !TRACE_KNOWN_FLAGS != 0 {
            return Err(AbiError::ReservedBits);
        }
        if (self.trace_id == 0) != (self.span_id == 0) {
            return Err(AbiError::InvalidTrace);
        }
        Ok(())
    }
}

/// Budget descriptor carried by cognitive syscalls.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InferenceBudget {
    /// Maximum output tokens. Zero means unspecified.
    pub max_tokens: u32,
    /// Maximum compute units. Zero means unspecified.
    pub max_compute_units: u32,
    /// Absolute deadline in monotonic nanoseconds, or zero when unset.
    pub deadline_ns: u64,
    /// Budget flags.
    pub flags: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
}

impl InferenceBudget {
    /// Unbounded budget placeholder. Kernel policy may still deny it.
    pub const UNBOUNDED: Self = Self {
        max_tokens: 0,
        max_compute_units: 0,
        deadline_ns: 0,
        flags: 0,
        reserved: 0,
    };

    /// Creates a bounded inference budget.
    pub const fn bounded(max_tokens: u32, max_compute_units: u32, deadline_ns: u64) -> Self {
        Self {
            max_tokens,
            max_compute_units,
            deadline_ns,
            flags: 0,
            reserved: 0,
        }
    }

    /// Returns `true` when at least one bound is set.
    pub const fn is_bounded(self) -> bool {
        self.max_tokens != 0 || self.max_compute_units != 0 || self.deadline_ns != 0
    }

    /// Validates reserved fields and known flags.
    pub const fn validate(self) -> AbiResult<()> {
        if self.reserved != 0 || self.flags & !INFERENCE_KNOWN_FLAGS != 0 {
            Err(AbiError::ReservedBits)
        } else {
            Ok(())
        }
    }
}

/// Syscall groups defined by the syscall interface.
#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallGroup {
    /// System calls.
    System = 0x0000,
    /// Task lifecycle calls.
    Task = 0x0100,
    /// Memory calls.
    Memory = 0x0200,
    /// Device calls.
    Device = 0x0300,
    /// Cognitive model and memory calls.
    Cognition = 0x0400,
    /// Security and capability calls.
    Security = 0x0500,
    /// Audit calls.
    Audit = 0x0600,
    /// Debug and tracing calls.
    Debug = 0x0700,
}

/// Stable syscall numbers for the MVK and near-term expansion table.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallNumber {
    /// Query ABI version, table version, and buffer limits.
    SysInfo = 0x0000,
    /// Cooperatively yield the current task.
    SysYield = 0x0001,
    /// Exit the current task.
    SysExit = 0x0002,
    /// Query monotonic time.
    SysTime = 0x0003,
    /// Create or update the current trace context.
    SysTraceContext = 0x0004,
    /// Spawn a task from a manifest buffer.
    SysTaskSpawn = 0x0100,
    /// Join a task.
    SysTaskJoin = 0x0101,
    /// Cancel a task.
    SysTaskCancel = 0x0102,
    /// Query task status.
    SysTaskStatus = 0x0103,
    /// Map a userspace memory range.
    SysMemMap = 0x0200,
    /// Unmap a userspace memory range.
    SysMemUnmap = 0x0201,
    /// Query memory statistics or a mapping.
    SysMemQuery = 0x0202,
    /// Share a userspace range.
    SysMemShare = 0x0203,
    /// Seal a shared memory handle.
    SysMemSeal = 0x0204,
    /// List devices.
    SysDeviceList = 0x0300,
    /// Open a device.
    SysDeviceOpen = 0x0301,
    /// Call a device operation.
    SysDeviceCall = 0x0302,
    /// Close a device.
    SysDeviceClose = 0x0303,
    /// List cognitive models.
    SysModelList = 0x0400,
    /// Open a cognitive model handle.
    SysModelOpen = 0x0401,
    /// Invoke deterministic model-device mediation.
    SysInfer = 0x0402,
    /// Query cognitive memory.
    SysMemoryQuery = 0x0403,
    /// Put a cognitive memory record.
    SysMemoryPut = 0x0404,
    /// Derive a child capability.
    SysCapDerive = 0x0500,
    /// Revoke a capability.
    SysCapRevoke = 0x0501,
    /// Query attestation material.
    SysAttest = 0x0502,
    /// Request kernel-mediated random bytes.
    SysRandom = 0x0503,
    /// Append an audit record.
    SysAuditAppend = 0x0600,
    /// Query audit records.
    SysAuditQuery = 0x0601,
    /// Verify audit chain ranges.
    SysAuditVerify = 0x0602,
}

impl SyscallNumber {
    /// Converts a raw register value into a known syscall number.
    pub const fn from_raw(raw: u64) -> Option<Self> {
        match raw {
            0x0000 => Some(Self::SysInfo),
            0x0001 => Some(Self::SysYield),
            0x0002 => Some(Self::SysExit),
            0x0003 => Some(Self::SysTime),
            0x0004 => Some(Self::SysTraceContext),
            0x0100 => Some(Self::SysTaskSpawn),
            0x0101 => Some(Self::SysTaskJoin),
            0x0102 => Some(Self::SysTaskCancel),
            0x0103 => Some(Self::SysTaskStatus),
            0x0200 => Some(Self::SysMemMap),
            0x0201 => Some(Self::SysMemUnmap),
            0x0202 => Some(Self::SysMemQuery),
            0x0203 => Some(Self::SysMemShare),
            0x0204 => Some(Self::SysMemSeal),
            0x0300 => Some(Self::SysDeviceList),
            0x0301 => Some(Self::SysDeviceOpen),
            0x0302 => Some(Self::SysDeviceCall),
            0x0303 => Some(Self::SysDeviceClose),
            0x0400 => Some(Self::SysModelList),
            0x0401 => Some(Self::SysModelOpen),
            0x0402 => Some(Self::SysInfer),
            0x0403 => Some(Self::SysMemoryQuery),
            0x0404 => Some(Self::SysMemoryPut),
            0x0500 => Some(Self::SysCapDerive),
            0x0501 => Some(Self::SysCapRevoke),
            0x0502 => Some(Self::SysAttest),
            0x0503 => Some(Self::SysRandom),
            0x0600 => Some(Self::SysAuditAppend),
            0x0601 => Some(Self::SysAuditQuery),
            0x0602 => Some(Self::SysAuditVerify),
            _ => None,
        }
    }

    /// Returns the raw syscall number.
    pub const fn raw(self) -> u32 {
        self as u32
    }

    /// Returns the stable syscall name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::SysInfo => "sys_info",
            Self::SysYield => "sys_yield",
            Self::SysExit => "sys_exit",
            Self::SysTime => "sys_time",
            Self::SysTraceContext => "sys_trace_context",
            Self::SysTaskSpawn => "sys_task_spawn",
            Self::SysTaskJoin => "sys_task_join",
            Self::SysTaskCancel => "sys_task_cancel",
            Self::SysTaskStatus => "sys_task_status",
            Self::SysMemMap => "sys_mem_map",
            Self::SysMemUnmap => "sys_mem_unmap",
            Self::SysMemQuery => "sys_mem_query",
            Self::SysMemShare => "sys_mem_share",
            Self::SysMemSeal => "sys_mem_seal",
            Self::SysDeviceList => "sys_device_list",
            Self::SysDeviceOpen => "sys_device_open",
            Self::SysDeviceCall => "sys_device_call",
            Self::SysDeviceClose => "sys_device_close",
            Self::SysModelList => "sys_model_list",
            Self::SysModelOpen => "sys_model_open",
            Self::SysInfer => "sys_infer",
            Self::SysMemoryQuery => "sys_memory_query",
            Self::SysMemoryPut => "sys_memory_put",
            Self::SysCapDerive => "sys_cap_derive",
            Self::SysCapRevoke => "sys_cap_revoke",
            Self::SysAttest => "sys_attest",
            Self::SysRandom => "sys_random",
            Self::SysAuditAppend => "sys_audit_append",
            Self::SysAuditQuery => "sys_audit_query",
            Self::SysAuditVerify => "sys_audit_verify",
        }
    }

    /// Returns the high-level group for this syscall.
    pub const fn group(self) -> SyscallGroup {
        match (self as u32) & 0xff00 {
            0x0100 => SyscallGroup::Task,
            0x0200 => SyscallGroup::Memory,
            0x0300 => SyscallGroup::Device,
            0x0400 => SyscallGroup::Cognition,
            0x0500 => SyscallGroup::Security,
            0x0600 => SyscallGroup::Audit,
            0x0700 => SyscallGroup::Debug,
            _ => SyscallGroup::System,
        }
    }
}

/// Execution context for syscall validation.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutionContext {
    /// Kernel initialization context.
    EarlyBoot = 0,
    /// Normal task context.
    Task = 1,
    /// Interrupt context.
    Interrupt = 2,
}

/// Audit event metadata for syscall descriptors.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditEvent {
    /// No audit event required.
    None = 0,
    /// System information queried.
    SystemInfo = 1,
    /// Task lifecycle changed.
    TaskLifecycle = 2,
    /// Memory mapping or sharing changed.
    Memory = 3,
    /// Device authority was used.
    Device = 4,
    /// Cognition authority was used.
    Cognition = 5,
    /// Capability state changed.
    Capability = 6,
    /// Security evidence was requested.
    Security = 7,
    /// Audit evidence changed or was verified.
    Audit = 8,
}

/// Syscall argument kind for descriptor metadata.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SyscallArgKind {
    /// No argument.
    None = 0,
    /// Plain integer value.
    Value = 1,
    /// Kernel handle.
    Handle = 2,
    /// User pointer address.
    UserPtr = 3,
    /// User buffer length.
    Length = 4,
    /// Flags bitmask.
    Flags = 5,
    /// Pointer to an ABI structure.
    StructPtr = 6,
}

/// Syscall arguments captured from the architecture calling convention.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallFrame {
    /// Syscall number. On x86_64 this corresponds to `rax`.
    pub number: u64,
    /// Up to six integer arguments. On x86_64 these map to `rdi`, `rsi`,
    /// `rdx`, `r10`, `r8`, and `r9` by the syscall ABI.
    pub args: [u64; 6],
    /// Trace context associated with this call.
    pub trace: TraceContext,
}

impl SyscallFrame {
    /// Creates a frame with a trace context.
    pub const fn traced(number: SyscallNumber, args: [u64; 6], trace: TraceContext) -> Self {
        Self {
            number: number as u64,
            args,
            trace,
        }
    }

    /// Creates a frame with no trace context.
    pub const fn new(number: SyscallNumber, args: [u64; 6]) -> Self {
        Self::traced(number, args, TraceContext::EMPTY)
    }

    /// Creates a frame from a raw syscall number.
    pub const fn raw(number: u64, args: [u64; 6]) -> Self {
        Self {
            number,
            args,
            trace: TraceContext::EMPTY,
        }
    }

    /// Returns the known syscall number or an ABI error.
    pub const fn syscall_number(self) -> AbiResult<SyscallNumber> {
        match SyscallNumber::from_raw(self.number) {
            Some(number) => Ok(number),
            None => Err(AbiError::UnknownSyscall),
        }
    }

    /// Validates the frame number and trace context.
    pub const fn validate(self) -> AbiResult<()> {
        match self.syscall_number() {
            Ok(_) => self.trace.validate(),
            Err(error) => Err(error),
        }
    }
}

/// Result register payload returned by the kernel dispatcher.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallReturn {
    /// Stable ABI status.
    pub status: AlaniStatus,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
    /// Primary integer value or handle.
    pub value: u64,
    /// Secondary count, commonly bytes written.
    pub detail: u64,
}

impl SyscallReturn {
    /// Successful syscall result with a primary value and detail count.
    pub const fn ok(value: u64, detail: u64) -> Self {
        Self {
            status: AlaniStatus::Ok,
            reserved: 0,
            value,
            detail,
        }
    }

    /// Error syscall result.
    pub const fn error(status: AlaniStatus) -> Self {
        Self {
            status,
            reserved: 0,
            value: 0,
            detail: 0,
        }
    }

    /// Validates reserved fields and status values.
    pub const fn validate(self) -> AbiResult<()> {
        if self.reserved != 0 {
            return Err(AbiError::ReservedBits);
        }
        status_to_result(self.status)
    }
}

/// Information returned by `sys_info`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SysInfo {
    /// Structure size in bytes.
    pub size: u32,
    /// Reserved for ABI evolution. Must be zero.
    pub reserved: u32,
    /// Current ABI version.
    pub abi_version: AbiVersion,
    /// Current syscall table version.
    pub syscall_table_version: AbiVersion,
    /// Number of syscalls in the table.
    pub syscall_count: u32,
    /// Maximum user buffer size accepted by the ABI helpers.
    pub max_user_buffer_len: u64,
    /// Supported ABI feature bits.
    pub feature_bits: u64,
}

impl SysInfo {
    /// Current system information payload.
    pub const CURRENT: Self = Self {
        size: size_of::<Self>() as u32,
        reserved: 0,
        abi_version: ALANI_ABI_VERSION,
        syscall_table_version: SYSCALL_TABLE_VERSION,
        syscall_count: SYSCALL_TABLE_LEN as u32,
        max_user_buffer_len: DEFAULT_MAX_USER_BUFFER_LEN,
        feature_bits: ALANI_ABI_FEATURES,
    };

    /// Validates size, reserved fields, and known feature bits.
    pub const fn validate(self) -> AbiResult<()> {
        if self.size < size_of::<Self>() as u32 {
            return Err(AbiError::InvalidVersion);
        }
        if self.reserved != 0 {
            return Err(AbiError::ReservedBits);
        }
        if self.feature_bits & !ALANI_ABI_FEATURES != 0 {
            return Err(AbiError::ReservedBits);
        }
        if self.syscall_count < SYSCALL_TABLE_LEN as u32 || self.max_user_buffer_len == 0 {
            return Err(AbiError::InvalidVersion);
        }
        match self.abi_version.validate() {
            Ok(()) => self.syscall_table_version.validate(),
            Err(error) => Err(error),
        }
    }
}

/// Static descriptor for one syscall table entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyscallDescriptor {
    /// Stable syscall number.
    pub number: SyscallNumber,
    /// Stable syscall name.
    pub name: &'static str,
    /// Required capability rights, or zero when unauthenticated.
    pub required_rights: CapabilityRights,
    /// Audit event emitted for authority-sensitive calls.
    pub audit_event: AuditEvent,
    /// Execution contexts where the syscall may run.
    pub context_flags: u32,
    /// Argument kind metadata.
    pub args: [SyscallArgKind; 6],
}

impl SyscallDescriptor {
    /// Returns `true` when the descriptor allows the execution context.
    pub const fn allows_context(self, context: ExecutionContext) -> bool {
        let required = match context {
            ExecutionContext::EarlyBoot => SYSCALL_CONTEXT_EARLY_BOOT,
            ExecutionContext::Task => SYSCALL_CONTEXT_TASK,
            ExecutionContext::Interrupt => SYSCALL_CONTEXT_INTERRUPT,
        };
        self.context_flags & required != 0
    }

    /// Validates descriptor table metadata.
    pub const fn validate(self) -> AbiResult<()> {
        if self.context_flags & !SYSCALL_CONTEXT_KNOWN_FLAGS != 0 {
            return Err(AbiError::ReservedBits);
        }
        if self.name.is_empty() {
            return Err(AbiError::InvalidArgument);
        }
        Ok(())
    }
}

/// Returns a descriptor for the given syscall number.
pub fn descriptor(number: SyscallNumber) -> Option<&'static SyscallDescriptor> {
    SYSCALL_TABLE
        .iter()
        .find(|descriptor| descriptor.number == number)
}

/// Returns a descriptor for a raw syscall number.
pub fn descriptor_from_raw(raw: u64) -> Option<&'static SyscallDescriptor> {
    SyscallNumber::from_raw(raw).and_then(descriptor)
}

const NONE: SyscallArgKind = SyscallArgKind::None;
const VALUE: SyscallArgKind = SyscallArgKind::Value;
const HANDLE: SyscallArgKind = SyscallArgKind::Handle;
const USER_PTR: SyscallArgKind = SyscallArgKind::UserPtr;
const LENGTH: SyscallArgKind = SyscallArgKind::Length;
const FLAGS: SyscallArgKind = SyscallArgKind::Flags;
const STRUCT_PTR: SyscallArgKind = SyscallArgKind::StructPtr;
const TASK_CONTEXT: u32 = SYSCALL_CONTEXT_TASK;
const BOOT_TASK_CONTEXT: u32 = SYSCALL_CONTEXT_EARLY_BOOT | SYSCALL_CONTEXT_TASK;
const ANY_CONTEXT: u32 =
    SYSCALL_CONTEXT_EARLY_BOOT | SYSCALL_CONTEXT_TASK | SYSCALL_CONTEXT_INTERRUPT;

/// Canonical syscall descriptor table.
pub const SYSCALL_TABLE: [SyscallDescriptor; SYSCALL_TABLE_LEN] = [
    SyscallDescriptor {
        number: SyscallNumber::SysInfo,
        name: "sys_info",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::SystemInfo,
        context_flags: ANY_CONTEXT,
        args: [USER_PTR, LENGTH, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysYield,
        name: "sys_yield",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::None,
        context_flags: TASK_CONTEXT,
        args: [NONE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysExit,
        name: "sys_exit",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::TaskLifecycle,
        context_flags: TASK_CONTEXT,
        args: [VALUE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTime,
        name: "sys_time",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::None,
        context_flags: ANY_CONTEXT,
        args: [NONE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTraceContext,
        name: "sys_trace_context",
        required_rights: CapabilityRights(CAP_TRACE_CONTEXT),
        audit_event: AuditEvent::None,
        context_flags: ANY_CONTEXT,
        args: [STRUCT_PTR, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskSpawn,
        name: "sys_task_spawn",
        required_rights: CapabilityRights(CAP_TASK_SPAWN),
        audit_event: AuditEvent::TaskLifecycle,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, STRUCT_PTR, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskJoin,
        name: "sys_task_join",
        required_rights: CapabilityRights(CAP_TASK_MANAGE),
        audit_event: AuditEvent::TaskLifecycle,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskCancel,
        name: "sys_task_cancel",
        required_rights: CapabilityRights(CAP_TASK_MANAGE),
        audit_event: AuditEvent::TaskLifecycle,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysTaskStatus,
        name: "sys_task_status",
        required_rights: CapabilityRights(CAP_TASK_MANAGE),
        audit_event: AuditEvent::None,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, USER_PTR, LENGTH, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemMap,
        name: "sys_mem_map",
        required_rights: CapabilityRights(CAP_MEMORY_MAP),
        audit_event: AuditEvent::Memory,
        context_flags: TASK_CONTEXT,
        args: [VALUE, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemUnmap,
        name: "sys_mem_unmap",
        required_rights: CapabilityRights(CAP_MEMORY_MAP),
        audit_event: AuditEvent::Memory,
        context_flags: TASK_CONTEXT,
        args: [VALUE, LENGTH, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemQuery,
        name: "sys_mem_query",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::None,
        context_flags: BOOT_TASK_CONTEXT,
        args: [USER_PTR, LENGTH, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemShare,
        name: "sys_mem_share",
        required_rights: CapabilityRights(CAP_MEMORY_SHARE),
        audit_event: AuditEvent::Memory,
        context_flags: TASK_CONTEXT,
        args: [VALUE, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemSeal,
        name: "sys_mem_seal",
        required_rights: CapabilityRights(CAP_MEMORY_SHARE),
        audit_event: AuditEvent::Memory,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceList,
        name: "sys_device_list",
        required_rights: CapabilityRights(CAP_DEVICE_LIST),
        audit_event: AuditEvent::None,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceOpen,
        name: "sys_device_open",
        required_rights: CapabilityRights(CAP_DEVICE_OPEN),
        audit_event: AuditEvent::Device,
        context_flags: TASK_CONTEXT,
        args: [VALUE, FLAGS, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceCall,
        name: "sys_device_call",
        required_rights: CapabilityRights(CAP_DEVICE_CALL),
        audit_event: AuditEvent::Device,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, VALUE, USER_PTR, USER_PTR, LENGTH, FLAGS],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysDeviceClose,
        name: "sys_device_close",
        required_rights: CapabilityRights(CAP_DEVICE_CALL),
        audit_event: AuditEvent::Device,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysModelList,
        name: "sys_model_list",
        required_rights: CapabilityRights::EMPTY,
        audit_event: AuditEvent::None,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysModelOpen,
        name: "sys_model_open",
        required_rights: CapabilityRights(CAP_COGNITION_INFER),
        audit_event: AuditEvent::Cognition,
        context_flags: TASK_CONTEXT,
        args: [VALUE, FLAGS, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysInfer,
        name: "sys_infer",
        required_rights: CapabilityRights(CAP_COGNITION_INFER),
        audit_event: AuditEvent::Cognition,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, USER_PTR, USER_PTR, STRUCT_PTR, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemoryQuery,
        name: "sys_memory_query",
        required_rights: CapabilityRights(CAP_COGNITION_INFER),
        audit_event: AuditEvent::Cognition,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, USER_PTR, LENGTH, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysMemoryPut,
        name: "sys_memory_put",
        required_rights: CapabilityRights(CAP_COGNITION_MEMORY_WRITE),
        audit_event: AuditEvent::Cognition,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysCapDerive,
        name: "sys_cap_derive",
        required_rights: CapabilityRights(CAP_CAPABILITY_ADMIN),
        audit_event: AuditEvent::Capability,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, VALUE, USER_PTR, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysCapRevoke,
        name: "sys_cap_revoke",
        required_rights: CapabilityRights(CAP_CAPABILITY_ADMIN),
        audit_event: AuditEvent::Capability,
        context_flags: TASK_CONTEXT,
        args: [HANDLE, NONE, NONE, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAttest,
        name: "sys_attest",
        required_rights: CapabilityRights(CAP_ATTEST),
        audit_event: AuditEvent::Security,
        context_flags: BOOT_TASK_CONTEXT,
        args: [USER_PTR, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysRandom,
        name: "sys_random",
        required_rights: CapabilityRights(CAP_RANDOM),
        audit_event: AuditEvent::Security,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAuditAppend,
        name: "sys_audit_append",
        required_rights: CapabilityRights(CAP_AUDIT_APPEND),
        audit_event: AuditEvent::Audit,
        context_flags: TASK_CONTEXT,
        args: [USER_PTR, LENGTH, FLAGS, NONE, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAuditQuery,
        name: "sys_audit_query",
        required_rights: CapabilityRights(CAP_AUDIT_QUERY),
        audit_event: AuditEvent::Audit,
        context_flags: TASK_CONTEXT,
        args: [VALUE, VALUE, USER_PTR, LENGTH, NONE, NONE],
    },
    SyscallDescriptor {
        number: SyscallNumber::SysAuditVerify,
        name: "sys_audit_verify",
        required_rights: CapabilityRights(CAP_AUDIT_VERIFY),
        audit_event: AuditEvent::Audit,
        context_flags: TASK_CONTEXT,
        args: [VALUE, VALUE, USER_PTR, LENGTH, NONE, NONE],
    },
];

/// Descriptor for the syscall component itself.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SyscallModuleDescriptor<'a> {
    /// Component name.
    pub name: &'a str,
    /// Component version marker.
    pub version: u32,
}

impl<'a> SyscallModuleDescriptor<'a> {
    /// Creates a syscall component descriptor.
    pub const fn new(name: &'a str, version: u32) -> Self {
        Self { name, version }
    }
}
