//! Security2 Architectural Protocol
//!
//! Abstracts security-specific functions from the DXE Foundation of UEFI Image Verification,
//! Trusted Computing Group (TCG) measured boot, and User Identity policy for image loading and consoles.
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

pub const PROTOCOL_GUID: efi::Guid = efi::Guid::from_fields(
    0x94ab2f58,
    0x1438,
    0x4ef1,
    0x91,
    0x52,
    &[0x18, 0x94, 0x1a, 0x3a, 0x0e, 0x68],
);

/// The DXE Foundation uses this service to measure and/or verify a UEFI image.
///
/// This service abstracts the invocation of Trusted Computing Group (TCG) measured boot, UEFI
/// Secure boot, and UEFI User Identity infrastructure. For the former two, the DXE Foundation
/// invokes the `file_authentication` with a `device_path` and corresponding image in
/// `file_buffer` memory. The TCG measurement code will record the `file_buffer` contents into the
/// appropriate PCR. The image verification logic will confirm the integrity and provenance of the
/// image in `file_buffer` of length `file_size`. The origin of the image will be `device_path` in
/// these cases.
/// If the `file_buffer` is `NULL`, the interface will determine if the `device_path` can be connected
/// in order to support the User Identification policy.
///
/// # Arguments
///
/// * `this` - The `Security2ArchProtocol` instance.
/// * `device_path` - A pointer to the device path of the file that is being dispatched.
///   This will optionally be used for logging.
/// * `file_buffer` - A pointer to the buffer with the UEFI file image.
/// * `file_size` - The size of the file.
/// * `boot_policy` - A boot policy that was used to call `LoadImage()` UEFI service. If
///   `file_authentication` is invoked not from the `LoadImage()`, `boot_policy` must be set to `false`.
///
/// # Return Values
///
/// * `efi::Status::SUCCESS` if the file specified by `device_path` and non-`NULL`
///   `file_buffer` did authenticate, and the platform policy dictates that the DXE Foundation may use the file.
/// * `efi::Status::SUCCESS` if the device path specified by `NULL` device path `device_path`
///   and non-`NULL` `file_buffer` did authenticate, and the platform policy dictates that the DXE Foundation
///   may execute the image in `file_buffer`.
/// * `efi::Status::SUCCESS` if `file_buffer` is `NULL` and the current user has permission to start
///   UEFI device drivers on the device path specified by `device_path`.
/// * `efi::Status::SECURITY_VIOLATION` if the file specified by `device_path` and `file_buffer` did not
///   authenticate, and the platform policy dictates that the file should be placed in the untrusted state.
///   The image has been added to the file execution table.
/// * `efi::Status::ACCESS_DENIED` if the file specified by `device_path` and `file_buffer` did not
///   authenticate, and the platform policy dictates that the DXE Foundation may not use the file.
/// * `efi::Status::SECURITY_VIOLATION` if `file_buffer` is `NULL` and the user has no
///   permission to start UEFI device drivers on the device path specified by `device_path`.
/// * `efi::Status::SECURITY_VIOLATION` if `file_buffer` is not `NULL` and the user has no permission to load
///   drivers from the device path specified by `device_path`. The image has been added into the list of the deferred images.
pub type FileAuthenticationState = extern "efiapi" fn(
    this: *const Protocol,
    device_path: *const DevicePathProtocol,
    file_buffer: *const core::ffi::c_void,
    file_size: usize,
    boot_policy: bool,
) -> efi::Status;

/// The `Security2ArchProtocol` is used to abstract platform-specific policy from the DXE Foundation.
/// This includes measuring the PE/COFF image prior to invoking, comparing the image against a policy
/// (whether a white-list/black-list of public image verification keys or registered hashes).
#[repr(C)]
pub struct Protocol {
    pub file_authentication: FileAuthenticationState,
}
