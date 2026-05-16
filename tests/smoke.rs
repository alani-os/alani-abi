use core::mem::{align_of, size_of};

use alani_abi::{
    abi_catalog, descriptor, descriptor_from_raw, sys_info, AbiCatalog, AbiError, AbiFeatureSet,
    AbiHeader, AbiVersion, AlaniStatus, CapabilityHandle, CapabilityRights, ExecutionContext,
    Handle, InferenceBudget, ObjectHandle, ObjectKind, SysInfo, SyscallFrame, SyscallGroup,
    SyscallNumber, SyscallReturn, TraceContext, UserBuffer, ABI_CATALOG, ABI_FEATURE_USER_BUFFERS,
    ABI_KNOWN_FEATURES, ALANI_ABI_FEATURES, ALANI_ABI_VERSION, CAP_COGNITION_INFER,
    CAP_DEVICE_CALL, CAP_TASK_SPAWN, DEFAULT_MAX_USER_BUFFER_LEN, INFERENCE_FLAG_DETERMINISTIC,
    SYSCALL_TABLE, SYSCALL_TABLE_LEN, TRACE_FLAG_SAMPLED, USER_BUFFER_READ, USER_BUFFER_WRITE,
};

#[test]
fn repository_identity_is_stable() {
    let info = alani_abi::component_info();

    assert_eq!(alani_abi::repository_name(), "alani-abi");
    assert_eq!(info.repository, "alani-abi");
    assert_eq!(info.status, alani_abi::ComponentStatus::Experimental);
    assert_eq!(
        alani_abi::module_names(),
        &["syscall", "handles", "errors", "version"]
    );
}

#[test]
fn version_and_feature_records_validate() {
    let current = ALANI_ABI_VERSION;
    let packed = current.packed();

    assert_eq!(AbiVersion::from_packed(packed), current);
    assert!(current.is_compatible_with(AbiVersion::new(0, 1, 0)));
    assert!(!AbiVersion::new(0, 0, 0).is_compatible_with(current));
    assert_eq!(
        AbiVersion {
            flags: 1,
            ..current
        }
        .validate(),
        Err(AbiError::ReservedBits)
    );

    let header = AbiHeader::new(size_of::<AbiHeader>() as u32, 0, current);
    assert_eq!(header.validate(size_of::<AbiHeader>() as u32, 0), Ok(()));
    assert_eq!(
        AbiHeader::new(4, 0, current).validate(size_of::<AbiHeader>() as u32, 0),
        Err(AbiError::InvalidVersion)
    );

    let features = AbiFeatureSet::from_bits(ALANI_ABI_FEATURES).unwrap();
    assert!(features.contains(AbiFeatureSet(ABI_FEATURE_USER_BUFFERS)));
    assert_eq!(
        AbiFeatureSet::from_bits(ABI_KNOWN_FEATURES << 1),
        Err(AbiError::ReservedBits)
    );
}

#[test]
fn status_and_error_mapping_is_stable() {
    assert_eq!(AlaniStatus::from_raw(0), Some(AlaniStatus::Ok));
    assert_eq!(
        AlaniStatus::from_raw(0xffff_ffff),
        Some(AlaniStatus::Internal)
    );
    assert_eq!(AlaniStatus::from_raw(99), None);
    assert_eq!(AlaniStatus::PermissionDenied.label(), "permission_denied");
    assert_eq!(
        AbiError::MissingCapability.status(),
        AlaniStatus::PermissionDenied
    );
    assert_eq!(
        alani_abi::status_to_result(AlaniStatus::DeadlineExceeded),
        Err(AbiError::DeadlineExceeded)
    );
}

#[test]
fn handle_and_capability_validation_fail_closed() {
    let rights = CapabilityRights::from_bits(CAP_TASK_SPAWN | CAP_DEVICE_CALL).unwrap();
    let handle = CapabilityHandle::new(7, rights, 42, 1);

    assert_eq!(Handle::INVALID.validate(), Err(AbiError::InvalidHandle));
    assert_eq!(
        CapabilityRights::from_bits(1 << 63),
        Err(AbiError::ReservedBits)
    );
    assert_eq!(handle.validate(), Ok(()));
    assert_eq!(handle.require(CapabilityRights(CAP_TASK_SPAWN)), Ok(()));
    assert_eq!(
        handle.require(CapabilityRights(CAP_COGNITION_INFER)),
        Err(AbiError::MissingCapability)
    );

    let object = ObjectHandle::new(Handle::new(11), ObjectKind::Device);
    assert_eq!(object.validate(), Ok(()));
    assert_eq!(ObjectKind::from_raw(4), Some(ObjectKind::Model));
    assert_eq!(ObjectKind::from_raw(99), None);
}

#[test]
fn user_buffers_validate_direction_reserved_bits_and_limits() {
    let bytes = [0_u8; 16];
    let read = UserBuffer::read_only(&bytes).unwrap();

    assert!(read.is_readable());
    assert!(!read.is_writable());
    assert_eq!(read.validate(), Ok(()));
    assert_eq!(read.checked_end(), Ok(read.ptr + read.len));
    assert_eq!(read.validate_alignment(1), Ok(()));
    assert_eq!(read.ptr_len_args(), [read.ptr, read.len]);

    let mut output = [0_u8; 8];
    let write = UserBuffer::write_only(&mut output).unwrap();
    assert!(write.is_writable());
    assert!(!write.is_readable());

    let read_write = UserBuffer::from_parts(0x1000, 32, USER_BUFFER_READ | USER_BUFFER_WRITE);
    assert_eq!(read_write.unwrap().validate(), Ok(()));
    assert_eq!(
        UserBuffer::new(0, 16, USER_BUFFER_READ).validate(),
        Err(AbiError::InvalidBuffer)
    );
    assert_eq!(
        UserBuffer::new(0x1000, DEFAULT_MAX_USER_BUFFER_LEN + 1, USER_BUFFER_READ).validate(),
        Err(AbiError::BufferTooLarge)
    );
    assert_eq!(
        UserBuffer::new(0x1000, 16, 1 << 31).validate(),
        Err(AbiError::ReservedBits)
    );
    assert_eq!(
        UserBuffer::new(0x1000, 16, 0).validate(),
        Err(AbiError::InvalidBuffer)
    );
    assert_eq!(
        UserBuffer::new(u64::MAX, 16, USER_BUFFER_READ).validate(),
        Err(AbiError::InvalidBuffer)
    );
    assert_eq!(
        UserBuffer::new(0x1003, 16, USER_BUFFER_READ).validate_alignment(4),
        Err(AbiError::InvalidBuffer)
    );
}

#[test]
fn trace_context_and_inference_budget_validate() {
    let trace = TraceContext::root(1, 2);
    let child = trace.child(3);

    assert_eq!(TraceContext::EMPTY.validate(), Ok(()));
    assert_eq!(trace.flags, TRACE_FLAG_SAMPLED);
    assert_eq!(child.parent_span_id, 2);
    assert_eq!(child.validate(), Ok(()));
    assert_eq!(
        TraceContext {
            trace_id: 1,
            span_id: 0,
            parent_span_id: 0,
            flags: 0,
            reserved: 0,
        }
        .validate(),
        Err(AbiError::InvalidTrace)
    );

    let mut budget = InferenceBudget::bounded(256, 1_000, 99);
    budget.flags = INFERENCE_FLAG_DETERMINISTIC;
    assert!(budget.is_bounded());
    assert_eq!(budget.validate(), Ok(()));
    budget.flags = 1 << 31;
    assert_eq!(budget.validate(), Err(AbiError::ReservedBits));
}

#[test]
fn syscall_numbers_and_descriptor_table_are_canonical() {
    assert_eq!(
        SyscallNumber::from_raw(0x0100),
        Some(SyscallNumber::SysTaskSpawn)
    );
    assert_eq!(
        SyscallNumber::from_raw(0x0400),
        Some(SyscallNumber::SysInfer)
    );
    assert_eq!(
        SyscallNumber::from_raw(0x0401),
        Some(SyscallNumber::SysModelList)
    );
    assert_eq!(
        SyscallNumber::from_raw(0x0402),
        Some(SyscallNumber::SysModelOpen)
    );
    assert_eq!(SyscallNumber::SysDeviceCall.raw(), 0x0302);
    assert_eq!(SyscallNumber::SysInfer.raw(), 0x0400);
    assert_eq!(SyscallNumber::SysInfer.name(), "sys_infer");
    assert_eq!(SyscallNumber::SysInfer.group(), SyscallGroup::Cognition);
    assert_eq!(descriptor_from_raw(0xffff), None);

    assert_eq!(SYSCALL_TABLE.len(), SYSCALL_TABLE_LEN);
    for entry in SYSCALL_TABLE {
        assert_eq!(entry.validate(), Ok(()));
        assert_eq!(entry.name, entry.number.name());
        assert_eq!(descriptor(entry.number), Some(&entry));
    }

    let infer = descriptor(SyscallNumber::SysInfer).unwrap();
    assert!(infer
        .required_rights
        .contains(CapabilityRights(CAP_COGNITION_INFER)));
    assert!(infer.requires_capability());
    assert!(infer.requires_audit());
    assert!(infer.allows_context(ExecutionContext::Task));
    assert!(!infer.allows_context(ExecutionContext::EarlyBoot));
}

#[test]
fn syscall_frames_returns_and_sys_info_validate() {
    let frame = SyscallFrame::new(SyscallNumber::SysInfo, [0; 6]);
    assert_eq!(frame.validate(), Ok(()));
    assert_eq!(
        frame
            .validate_dispatch(ExecutionContext::EarlyBoot, None)
            .unwrap()
            .number,
        SyscallNumber::SysInfo
    );
    assert_eq!(frame.syscall_number(), Ok(SyscallNumber::SysInfo));
    assert_eq!(
        SyscallFrame::raw(0xffff, [0; 6]).validate(),
        Err(AbiError::UnknownSyscall)
    );

    let infer = SyscallFrame::new(SyscallNumber::SysInfer, [0; 6]);
    assert_eq!(
        infer.validate_for_context(ExecutionContext::EarlyBoot),
        Err(AbiError::InvalidContext)
    );
    assert_eq!(
        infer.validate_dispatch(ExecutionContext::Task, None),
        Err(AbiError::MissingCapability)
    );
    let cap = CapabilityHandle::new(9, CapabilityRights(CAP_COGNITION_INFER), 42, 1);
    assert_eq!(
        infer
            .validate_dispatch(ExecutionContext::Task, Some(cap))
            .unwrap()
            .number,
        SyscallNumber::SysInfer
    );

    let invalid_trace = SyscallFrame {
        trace: TraceContext {
            trace_id: 1,
            span_id: 0,
            parent_span_id: 0,
            flags: 0,
            reserved: 0,
        },
        ..frame
    };
    assert_eq!(invalid_trace.validate(), Err(AbiError::InvalidTrace));

    assert_eq!(SyscallReturn::ok(7, 8).validate(), Ok(()));
    assert_eq!(
        SyscallReturn::error(AlaniStatus::PermissionDenied).validate(),
        Err(AbiError::MissingCapability)
    );
    assert_eq!(
        SyscallReturn {
            reserved: 1,
            ..SyscallReturn::ok(0, 0)
        }
        .validate(),
        Err(AbiError::ReservedBits)
    );

    let info = sys_info();
    assert_eq!(info, SysInfo::CURRENT);
    assert_eq!(info.validate(), Ok(()));
    assert_eq!(info.syscall_count, SYSCALL_TABLE_LEN as u32);
    assert_eq!(info.max_user_buffer_len, DEFAULT_MAX_USER_BUFFER_LEN);
    assert_eq!(info.feature_bits, ALANI_ABI_FEATURES);

    let mut bad_info = info;
    bad_info.feature_bits = 1 << 63;
    assert_eq!(bad_info.validate(), Err(AbiError::ReservedBits));
}

#[test]
fn abi_catalog_exposes_current_contract() {
    assert_eq!(abi_catalog(), ABI_CATALOG);
    assert_eq!(AbiCatalog::current().validate(), Ok(()));
    assert_eq!(AbiCatalog::current().sys_info(), SysInfo::CURRENT);
    assert_eq!(
        AbiCatalog::current()
            .syscall_descriptor(SyscallNumber::SysRandom)
            .unwrap()
            .name,
        "sys_random"
    );
}

#[test]
fn repr_c_layouts_remain_stable() {
    assert_eq!(size_of::<AbiVersion>(), 8);
    assert_eq!(size_of::<AbiHeader>(), 24);
    assert_eq!(size_of::<CapabilityHandle>(), 32);
    assert_eq!(size_of::<ObjectHandle>(), 16);
    assert_eq!(size_of::<UserBuffer>(), 24);
    assert_eq!(size_of::<TraceContext>(), 32);
    assert_eq!(size_of::<InferenceBudget>(), 24);
    assert_eq!(size_of::<SyscallFrame>(), 88);
    assert_eq!(size_of::<SyscallReturn>(), 24);
    assert_eq!(size_of::<SysInfo>(), 48);

    assert_eq!(align_of::<SyscallFrame>(), 8);
    assert_eq!(align_of::<SysInfo>(), 8);
}
