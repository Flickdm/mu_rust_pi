//! Security Architectural Protocol
//!
//! Security Architectural Protocol as defined in PI Specification VOLUME 2 DXE
//!
//! Used to provide Security services.  Specifically, depending upon the
//! authentication state of a discovered driver in a Firmware Volume, the
//! portable DXE Core Dispatcher will call into the Security Architectural
//! Protocol (SAP) with the authentication state of the driver.
//!
//! This call-out allows for OEM-specific policy decisions to be made, such
//! as event logging for attested boots, locking flash in response to discovering
//! an unsigned driver or failed signature check, or other exception response.
//!
//! The SAP can also change system behavior by having the DXE core put a driver
//! in the Schedule-On-Request (SOR) state.  This will allow for later disposition
//! of the driver by platform agent, such as Platform BDS.
//!
//! See <https://uefi.org/specs/PI/1.8A/V2_DXE_Architectural_Protocols.html#security-architectural-protocols>
//!
//! ## License
//!
//! Copyright (C) Microsoft Corporation. All rights reserved.
//!
//! SPDX-License-Identifier: BSD-2-Clause-Patent

use r_efi::efi;
use r_efi::protocols::device_path::Protocol as DevicePathProtocol;


///  Security Architectural Protocol
///
///  Used to provide Security services.  Specifically, depending upon the
///  authentication state of a discovered driver in a Firmware Volume, the
///  portable DXE Core Dispatcher will call into the Security Architectural
///  Protocol (SAP) with the authentication state of the driver.
///
///  This call-out allows for OEM-specific policy decisions to be made, such
///  as event logging for attested boots, locking flash in response to discovering
///  an unsigned driver or failed signature check, or other exception response.
///
///  The SAP can also change system behavior by having the DXE core put a driver
///  in the Schedule-On-Request (SOR) state.  This will allow for later disposition
///  of the driver by platform agent, such as Platform BDS.

pub const PROTOCOL_GUID: efi::Guid = efi::Guid::from_fields(
    0xa46423e3,
    0x4617,
    0x49f1,
    0xb9,
    0xff,
    &[0xd1, 0xbf, 0xa9, 0x11, 0x58, 0x39],
);

/// # Documentation
///
/// UEFI Platform Initialization Specification, Release 1.8A, Section II-12.8.1
/// The `SecurityArchProtocol` (SAP) is used to abstract platform-specific
/// policy from the DXE core response to an attempt to use a file that returns a
/// given status for the authentication check from the section extraction protocol.
///
/// The possible responses in a given SAP implementation may include locking
/// flash upon failure to authenticate, attestation logging for all signed drivers,
/// and other exception operations. The `file` parameter allows for possible logging
/// within the SAP of the driver.
///
/// If `file` is `None`, then `Status::InvalidParameter` is returned.
///
/// If the file specified by `file` with an authentication status specified by
/// `authentication_status` is safe for the DXE Core to use, then `Status::Success` is returned.
///
/// If the file specified by `file` with an authentication status specified by
/// `authentication_status` is not safe for the DXE Core to use under any circumstances,
/// then `Status::AccessDenied` is returned.
///
/// If the file specified by `file` with an authentication status specified by
/// `authentication_status` is not safe for the DXE Core to use right now, but it
/// might be possible to use it at a future time, then `Status::SecurityViolation` is
/// returned.
///
/// # Arguments
///
/// * `this` - The `SecurityArchProtocol` instance.
/// * `authentication_status` - This is the authentication type returned from the Section
///   Extraction protocol. See the Section Extraction Protocol Specification for details on this type.
/// * `file` - This is a pointer to the device path of the file that is being dispatched.
///   This will optionally be used for logging.
///
/// # Return Values
///
/// * `Status::Success` if the file specified by `file` did authenticate, and the
///   platform policy dictates that the DXE Core may use `file`.
/// * `Status::InvalidParameter` if `file` is `None`.
/// * `Status::SecurityViolation` if the file specified by `file` did not authenticate, and
///   the platform policy dictates that `file` should be placed in the untrusted state.
///   A file may be promoted from the untrusted to the trusted state at a future time
///   with a call to the `trust` DXE Service.
/// * `Status::AccessDenied` if the file specified by `file` did not authenticate, and
///   the platform policy dictates that `file` should not be used for any purpose.
pub type FileAuthenticationState = extern "efiapi" fn(
    this: *const Protocol,
    authentication_status: u32,
    file: *const DevicePathProtocol
) -> efi::Status;

///
/// The EFI_SECURITY_ARCH_PROTOCOL is used to abstract platform-specific policy
/// from the DXE core.  This includes locking flash upon failure to authenticate,
/// attestation logging, and other exception operations.
///
#[repr(C)]
pub struct Protocol {
    pub file_authentication_state: FileAuthenticationState,
}
