// Copyright 2017 Marcus Heese
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![allow(non_camel_case_types, non_snake_case)]

pub use pkcs11_sys::*;

use crate::types::padding::*;
use std::convert::TryInto;
use std::ptr;

pub struct CkFlags {
    pub flags: CK_FLAGS,
}

impl CkFlags {
    pub fn new(flags: CK_FLAGS) -> Self {
        Self { flags: flags }
    }

    fn set_flag(&mut self, flag: CK_FLAGS, b: bool) {
        if b {
            self.flags |= flag;
        } else {
            self.flags &= !flag;
        }
    }

    pub fn set_token_present(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_TOKEN_PRESENT, b);
        self
    }

    pub fn set_removable_device(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_REMOVABLE_DEVICE, b);
        self
    }

    pub fn set_hw_slot(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_HW_SLOT, b);
        self
    }

    pub fn set_array_attribute(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_ARRAY_ATTRIBUTE, b);
        self
    }

    pub fn set_rng(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RNG, b);
        self
    }

    pub fn set_write_protected(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_WRITE_PROTECTED, b);
        self
    }

    pub fn set_login_required(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_LOGIN_REQUIRED, b);
        self
    }

    pub fn set_user_pin_initialized(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_INITIALIZED, b);
        self
    }

    pub fn set_restore_key_not_needed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RESTORE_KEY_NOT_NEEDED, b);
        self
    }

    pub fn set_clock_on_token(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_CLOCK_ON_TOKEN, b);
        self
    }

    pub fn set_protected_authentication_path(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_PROTECTED_AUTHENTICATION_PATH, b);
        self
    }

    pub fn set_dual_crypto_operations(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DUAL_CRYPTO_OPERATIONS, b);
        self
    }

    pub fn set_token_initialized(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_TOKEN_INITIALIZED, b);
        self
    }

    pub fn set_secondary_authentication(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SECONDARY_AUTHENTICATION, b);
        self
    }

    pub fn set_user_pin_count_low(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_COUNT_LOW, b);
        self
    }

    pub fn set_user_pin_final_try(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_FINAL_TRY, b);
        self
    }

    pub fn set_user_pin_locked(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_LOCKED, b);
        self
    }

    pub fn set_user_pin_to_be_changed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_PIN_TO_BE_CHANGED, b);
        self
    }

    pub fn set_so_pin_count_low(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_COUNT_LOW, b);
        self
    }

    pub fn set_so_pin_final_try(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_FINAL_TRY, b);
        self
    }

    pub fn set_so_pin_locked(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_LOCKED, b);
        self
    }

    pub fn set_so_pin_to_be_changed(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SO_PIN_TO_BE_CHANGED, b);
        self
    }

    pub fn set_rw_session(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_RW_SESSION, b);
        self
    }

    pub fn set_serial_session(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SERIAL_SESSION, b);
        self
    }

    pub fn set_next_otp(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_NEXT_OTP, b);
        self
    }

    pub fn set_exclude_time(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_TIME, b);
        self
    }

    pub fn set_exclude_counter(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_COUNTER, b);
        self
    }

    pub fn set_exclude_challenge(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_CHALLENGE, b);
        self
    }

    pub fn set_exclude_pin(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXCLUDE_PIN, b);
        self
    }

    pub fn set_user_friendly_otp(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_USER_FRIENDLY_OTP, b);
        self
    }

    pub fn set_hw(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_HW, b);
        self
    }

    pub fn set_encrypt(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_ENCRYPT, b);
        self
    }

    pub fn set_decrypt(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DECRYPT, b);
        self
    }

    pub fn set_digest(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DIGEST, b);
        self
    }

    pub fn set_sign(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SIGN, b);
        self
    }

    pub fn set_sign_recover(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_SIGN_RECOVER, b);
        self
    }

    pub fn set_verify(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_VERIFY, b);
        self
    }

    pub fn set_verify_recover(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_VERIFY_RECOVER, b);
        self
    }

    pub fn set_generate(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_GENERATE, b);
        self
    }

    pub fn set_generate_key_pair(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_GENERATE_KEY_PAIR, b);
        self
    }

    pub fn set_wrap(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_WRAP, b);
        self
    }

    pub fn set_unwrap(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_UNWRAP, b);
        self
    }

    pub fn set_derive(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DERIVE, b);
        self
    }

    pub fn set_extension(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EXTENSION, b);
        self
    }

    pub fn set_ec_f_p(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_F_P, b);
        self
    }

    pub fn set_ec_namedcurve(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_NAMEDCURVE, b);
        self
    }

    pub fn set_ec_uncompress(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_UNCOMPRESS, b);
        self
    }

    pub fn set_ec_compress(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_EC_COMPRESS, b);
        self
    }

    pub fn set_dont_block(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_DONT_BLOCK, b);
        self
    }

    pub fn set_library_cant_create_os_threads(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_LIBRARY_CANT_CREATE_OS_THREADS, b);
        self
    }

    pub fn set_os_locking_ok(&mut self, b: bool) -> &mut Self {
        self.set_flag(CKF_OS_LOCKING_OK, b);
        self
    }
}

impl Default for CkFlags {
    fn default() -> Self {
        Self { flags: 0 }
    }
}

impl From<CkFlags> for CK_FLAGS {
    fn from(ck_flags: CkFlags) -> Self {
        ck_flags.flags
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CkVersion {
    pub major: ::std::os::raw::c_uchar,
    pub minor: ::std::os::raw::c_uchar,
}

impl CkVersion {
    pub fn new(major: ::std::os::raw::c_uchar, minor: ::std::os::raw::c_uchar) -> Self {
        Self { major, minor }
    }
}

impl Default for CkVersion {
    fn default() -> Self {
        // FIXME: is there a default version we want to supply here?
        Self { major: 1, minor: 0 }
    }
}

impl From<CkVersion> for CK_VERSION {
    fn from(ck_version: CkVersion) -> Self {
        Self {
            major: ck_version.major,
            minor: ck_version.minor,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CkInfo {
    pub cryptoki_version: CK_VERSION,
    pub manufacturer_id: BlankPaddedUtf8String32,
    pub flags: CK_FLAGS,
    pub library_description: BlankPaddedUtf8String32,
    pub library_version: CK_VERSION,
}

impl CkInfo {
    pub fn new() -> Self {
        Self {
            cryptoki_version: Default::default(),
            manufacturer_id: Default::default(),
            flags: CkFlags::default().into(),
            library_description: Default::default(),
            library_version: Default::default(),
        }
    }

    pub fn with_cryptoki_version(&mut self, cryptoki_version: CK_VERSION) -> &mut Self {
        self.cryptoki_version = cryptoki_version;
        self
    }

    pub fn with_manufacturer_id(&mut self, manufacturer_id: BlankPaddedUtf8String32) -> &mut Self {
        self.manufacturer_id = manufacturer_id;
        self
    }

    pub fn with_flags(&mut self, flags: CK_FLAGS) -> &mut Self {
        self.flags = flags;
        self
    }

    pub fn with_library_description(
        &mut self,
        library_description: BlankPaddedUtf8String32,
    ) -> &mut Self {
        self.library_description = library_description;
        self
    }

    pub fn with_library_version(&mut self, library_version: CK_VERSION) -> &mut Self {
        self.library_version = library_version;
        self
    }

    pub fn build(&self) -> CK_INFO {
        CK_INFO {
            cryptokiVersion: self.cryptoki_version,
            manufacturerID: self.manufacturer_id.0,
            flags: self.flags,
            libraryDescription: self.library_description.0,
            libraryVersion: self.library_version,
        }
    }
}

impl From<CkInfo> for CK_INFO {
    fn from(ck_info: CkInfo) -> Self {
        Self {
            cryptokiVersion: ck_info.cryptoki_version,
            manufacturerID: ck_info.manufacturer_id.0,
            flags: ck_info.flags,
            libraryDescription: ck_info.library_description.0,
            libraryVersion: ck_info.library_version,
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct CkSlotInfo {
    pub slot_description: BlankPaddedUtf8String64,
    pub manufacturer_id: BlankPaddedUtf8String32,
    pub flags: CK_FLAGS,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
}

impl CkSlotInfo {
    pub fn new() -> Self {
        Self {
            slot_description: Default::default(),
            manufacturer_id: Default::default(),
            flags: CkFlags::default().into(),
            hardware_version: Default::default(),
            firmware_version: Default::default(),
        }
    }

    pub fn with_slot_description(
        &mut self,
        slot_description: BlankPaddedUtf8String64,
    ) -> &mut Self {
        self.slot_description = slot_description;
        self
    }

    pub fn with_manufacturer_id(&mut self, manufacturer_id: BlankPaddedUtf8String32) -> &mut Self {
        self.manufacturer_id = manufacturer_id;
        self
    }

    pub fn with_flags(&mut self, flags: CK_FLAGS) -> &mut Self {
        self.flags = flags;
        self
    }

    pub fn with_hardware_version(&mut self, hardware_version: CK_VERSION) -> &mut Self {
        self.hardware_version = hardware_version;
        self
    }

    pub fn with_firmware_version(&mut self, firmware_version: CK_VERSION) -> &mut Self {
        self.firmware_version = firmware_version;
        self
    }
}

impl From<CkSlotInfo> for CK_SLOT_INFO {
    fn from(ck_slot_info: CkSlotInfo) -> Self {
        Self {
            slotDescription: ck_slot_info.slot_description.0,
            manufacturerID: ck_slot_info.manufacturer_id.0,
            flags: ck_slot_info.flags,
            hardwareVersion: ck_slot_info.hardware_version,
            firmwareVersion: ck_slot_info.firmware_version,
        }
    }
}

#[derive(Debug, Copy, Clone)]
#[repr(C)]
pub struct CkTokenInfo {
    pub label: BlankPaddedUtf8String32,
    pub manufacturer_id: BlankPaddedUtf8String32,
    pub model: BlankPaddedUtf8String16,
    pub serial_number: BlankPaddedUtf8String16,
    pub flags: CK_FLAGS,
    pub ul_max_session_count: ::std::os::raw::c_ulong,
    pub ul_session_count: ::std::os::raw::c_ulong,
    pub ul_max_rw_session_count: ::std::os::raw::c_ulong,
    pub ul_rw_session_count: ::std::os::raw::c_ulong,
    pub ul_max_pin_len: ::std::os::raw::c_ulong,
    pub ul_min_pin_len: ::std::os::raw::c_ulong,
    pub ul_total_public_memory: ::std::os::raw::c_ulong,
    pub ul_free_public_memory: ::std::os::raw::c_ulong,
    pub ul_total_private_memory: ::std::os::raw::c_ulong,
    pub ul_free_private_memory: ::std::os::raw::c_ulong,
    pub hardware_version: _CK_VERSION,
    pub firmware_version: _CK_VERSION,
    pub utc_time: BlankPaddedUtf8String16,
}

impl CkTokenInfo {
    pub fn new() -> Self {
        Self {
            label: Default::default(),
            manufacturer_id: Default::default(),
            model: Default::default(),
            serial_number: Default::default(),
            flags: CkFlags::default().into(),
            ul_max_session_count: Default::default(),
            ul_session_count: Default::default(),
            ul_max_rw_session_count: Default::default(),
            ul_rw_session_count: Default::default(),
            ul_max_pin_len: Default::default(),
            ul_min_pin_len: Default::default(),
            ul_total_public_memory: Default::default(),
            ul_free_public_memory: Default::default(),
            ul_total_private_memory: Default::default(),
            ul_free_private_memory: Default::default(),
            hardware_version: Default::default(),
            firmware_version: Default::default(),
            utc_time: Default::default(),
        }
    }

    pub fn with_label(&mut self, label: BlankPaddedUtf8String32) -> &mut Self {
        self.label = label;
        self
    }

    pub fn with_manufacturer_id(&mut self, manufacturer_id: BlankPaddedUtf8String32) -> &mut Self {
        self.manufacturer_id = manufacturer_id;
        self
    }

    pub fn with_model(&mut self, model: BlankPaddedUtf8String16) -> &mut Self {
        self.model = model;
        self
    }

    pub fn with_serial_number(&mut self, serial_number: BlankPaddedUtf8String16) -> &mut Self {
        self.serial_number = serial_number;
        self
    }

    pub fn with_flags(&mut self, flags: CK_FLAGS) -> &mut Self {
        self.flags = flags;
        self
    }

    pub fn with_ul_max_session_count(
        &mut self,
        ul_max_session_count: ::std::os::raw::c_ulong,
    ) -> &mut Self {
        self.ul_max_session_count = ul_max_session_count;
        self
    }

    pub fn with_ul_session_count(
        &mut self,
        ul_session_count: ::std::os::raw::c_ulong,
    ) -> &mut Self {
        self.ul_session_count = ul_session_count;
        self
    }

    pub fn with_ul_max_rw_session_count(
        &mut self,
        ul_max_rw_session_count: ::std::os::raw::c_ulong,
    ) -> &mut Self {
        self.ul_max_rw_session_count = ul_max_rw_session_count;
        self
    }

    pub fn with_ul_rw_session_count(
        &mut self,
        ul_rw_session_count: ::std::os::raw::c_ulong,
    ) -> &mut Self {
        self.ul_rw_session_count = ul_rw_session_count;
        self
    }

    pub fn with_ul_max_pin_len(&mut self, ul_max_pin_len: ::std::os::raw::c_ulong) -> &mut Self {
        self.ul_max_pin_len = ul_max_pin_len;
        self
    }

    pub fn with_ul_min_pin_len(&mut self, ul_min_pin_len: ::std::os::raw::c_ulong) -> &mut Self {
        self.ul_min_pin_len = ul_min_pin_len;
        self
    }

    pub fn with_ul_total_public_memory(
        &mut self,
        ul_total_public_memory: ::std::os::raw::c_ulong,
    ) -> &mut Self {
        self.ul_total_public_memory = ul_total_public_memory;
        self
    }

    pub fn with_ul_free_public_memory(
        &mut self,
        ul_free_public_memory: ::std::os::raw::c_ulong,
    ) -> &mut Self {
        self.ul_free_public_memory = ul_free_public_memory;
        self
    }

    pub fn with_ul_total_private_memory(
        &mut self,
        ul_total_private_memory: ::std::os::raw::c_ulong,
    ) -> &mut Self {
        self.ul_total_private_memory = ul_total_private_memory;
        self
    }

    pub fn with_ul_free_private_memory(
        &mut self,
        ul_free_private_memory: ::std::os::raw::c_ulong,
    ) -> &mut Self {
        self.ul_free_private_memory = ul_free_private_memory;
        self
    }

    pub fn with_hardware_version(&mut self, hardware_version: CK_VERSION) -> &mut Self {
        self.hardware_version = hardware_version;
        self
    }

    pub fn with_firmware_version(&mut self, firmware_version: CK_VERSION) -> &mut Self {
        self.firmware_version = firmware_version;
        self
    }

    pub fn with_utc_time(&mut self, utc_time: BlankPaddedUtf8String16) -> &mut Self {
        self.utc_time = utc_time;
        self
    }
}

pub enum CkCInitializeArgs {
    NoThreads,
    OsThreads,
    // TODO: add variants for custom mutexes here.
}

impl From<CkCInitializeArgs> for CK_C_INITIALIZE_ARGS {
    fn from(ck_c_initialize_args: CkCInitializeArgs) -> Self {
        let mut flags = CkFlags::default();
        match ck_c_initialize_args {
            CkCInitializeArgs::NoThreads => {
                flags.set_os_locking_ok(false);
                Self {
                    flags: flags.into(),
                    CreateMutex: None,
                    DestroyMutex: None,
                    LockMutex: None,
                    UnlockMutex: None,
                    pReserved: ptr::null_mut(),
                }
            }
            CkCInitializeArgs::OsThreads => {
                flags.set_os_locking_ok(true);
                Self {
                    flags: flags.into(),
                    CreateMutex: None,
                    DestroyMutex: None,
                    LockMutex: None,
                    UnlockMutex: None,
                    pReserved: ptr::null_mut(),
                }
            }
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum CkAttributeType {
    CkaBase,
    CkaClass,
    CkaCopyable,
    CkaDecrypt,
    CkaDerive,
    CkaEncrypt,
    CkaExtractable,
    CkaKeyType,
    CkaLabel,
    CkaModifiable,
    CkaModulusBits,
    CkaPrime,
    CkaPrivate,
    CkaPublicExponent,
    CkaSensitive,
    CkaSign,
    CkaSignRecover,
    CkaToken,
    CkaUnwrap,
    CkaValue,
    CkaValueLen,
    CkaVerify,
    CkaVerifyRecover,
    CkaWrap,
}

impl From<CkAttributeType> for CK_ATTRIBUTE_TYPE {
    fn from(ck_attribute_type: CkAttributeType) -> Self {
        match ck_attribute_type {
            CkAttributeType::CkaBase => CKA_BASE,
            CkAttributeType::CkaClass => CKA_CLASS,
            CkAttributeType::CkaCopyable => CKA_COPYABLE,
            CkAttributeType::CkaDecrypt => CKA_DECRYPT,
            CkAttributeType::CkaDerive => CKA_DERIVE,
            CkAttributeType::CkaEncrypt => CKA_ENCRYPT,
            CkAttributeType::CkaExtractable => CKA_EXTRACTABLE,
            CkAttributeType::CkaKeyType => CKA_KEY_TYPE,
            CkAttributeType::CkaLabel => CKA_LABEL,
            CkAttributeType::CkaModifiable => CKA_MODIFIABLE,
            CkAttributeType::CkaModulusBits => CKA_MODULUS_BITS,
            CkAttributeType::CkaPrime => CKA_PRIME,
            CkAttributeType::CkaPrivate => CKA_PRIVATE,
            CkAttributeType::CkaPublicExponent => CKA_PUBLIC_EXPONENT,
            CkAttributeType::CkaSensitive => CKA_SENSITIVE,
            CkAttributeType::CkaSign => CKA_SIGN,
            CkAttributeType::CkaSignRecover => CKA_SIGN_RECOVER,
            CkAttributeType::CkaToken => CKA_TOKEN,
            CkAttributeType::CkaUnwrap => CKA_UNWRAP,
            CkAttributeType::CkaValue => CKA_VALUE,
            CkAttributeType::CkaValueLen => CKA_VALUE_LEN,
            CkAttributeType::CkaVerify => CKA_VERIFY,
            CkAttributeType::CkaVerifyRecover => CKA_VERIFY_RECOVER,
            CkAttributeType::CkaWrap => CKA_WRAP,
        }
    }
}

#[derive(Debug, PartialEq)]
#[repr(C)]
pub enum CkAttribute<'a> {
    CkaBase(&'a mut CK_BYTE),
    CkaClass(&'a mut CK_OBJECT_CLASS),
    CkaCopyable(&'a mut CK_BBOOL),
    CkaDecrypt(&'a mut CK_BBOOL),
    CkaDerive(&'a mut CK_BBOOL),
    CkaEncrypt(&'a mut CK_BBOOL),
    CkaExtractable(&'a mut CK_BBOOL),
    CkaKeyType(&'a mut CK_KEY_TYPE),
    CkaLabel(&'a mut [CK_UTF8CHAR]),
    CkaModifiable(&'a mut CK_BBOOL),
    CkaModulusBits(&'a mut CK_ULONG),
    CkaPrime(&'a mut [CK_BYTE]),
    CkaPrivate(&'a mut CK_BBOOL),
    CkaPublicExponent(&'a mut [CK_BYTE]),
    CkaSensitive(&'a mut CK_BBOOL),
    CkaSign(&'a mut CK_BBOOL),
    CkaSignRecover(&'a mut CK_BBOOL),
    CkaToken(&'a mut CK_BBOOL),
    CkaUnwrap(&'a mut CK_BBOOL),
    CkaValue(&'a mut [u8]),
    CkaValueLen(&'a mut CK_ULONG),
    CkaVerify(&'a mut CK_BBOOL),
    CkaVerifyRecover(&'a mut CK_BBOOL),
    CkaWrap(&'a mut CK_BBOOL),
}

impl CkAttribute<'_> {
    /// Returns the corresponding CK_ATTRIBUTE_TYPE for this CkAttribute.
    pub fn get_attribute_type(&self) -> CkAttributeType {
        match self {
            CkAttribute::CkaBase(_) => CkAttributeType::CkaBase,
            CkAttribute::CkaClass(_) => CkAttributeType::CkaClass,
            CkAttribute::CkaCopyable(_) => CkAttributeType::CkaCopyable,
            CkAttribute::CkaDecrypt(_) => CkAttributeType::CkaDecrypt,
            CkAttribute::CkaDerive(_) => CkAttributeType::CkaDerive,
            CkAttribute::CkaEncrypt(_) => CkAttributeType::CkaEncrypt,
            CkAttribute::CkaExtractable(_) => CkAttributeType::CkaExtractable,
            CkAttribute::CkaKeyType(_) => CkAttributeType::CkaKeyType,
            CkAttribute::CkaLabel(_) => CkAttributeType::CkaLabel,
            CkAttribute::CkaModifiable(_) => CkAttributeType::CkaModifiable,
            CkAttribute::CkaModulusBits(_) => CkAttributeType::CkaModulusBits,
            CkAttribute::CkaPrime(_) => CkAttributeType::CkaPrime,
            CkAttribute::CkaPrivate(_) => CkAttributeType::CkaPrivate,
            CkAttribute::CkaPublicExponent(_) => CkAttributeType::CkaPublicExponent,
            CkAttribute::CkaSensitive(_) => CkAttributeType::CkaSensitive,
            CkAttribute::CkaSign(_) => CkAttributeType::CkaSign,
            CkAttribute::CkaSignRecover(_) => CkAttributeType::CkaSignRecover,
            CkAttribute::CkaToken(_) => CkAttributeType::CkaToken,
            CkAttribute::CkaUnwrap(_) => CkAttributeType::CkaUnwrap,
            CkAttribute::CkaValue(_) => CkAttributeType::CkaValue,
            CkAttribute::CkaValueLen(_) => CkAttributeType::CkaValueLen,
            CkAttribute::CkaVerify(_) => CkAttributeType::CkaVerify,
            CkAttribute::CkaVerifyRecover(_) => CkAttributeType::CkaVerifyRecover,
            CkAttribute::CkaWrap(_) => CkAttributeType::CkaWrap,
        }
    }

    /// Returns the length in bytes of the objects contained by this CkAttribute.
    fn get_attribute_len(&self) -> CK_ULONG {
        let len = match self {
            CkAttribute::CkaCopyable(_)
            | CkAttribute::CkaDecrypt(_)
            | CkAttribute::CkaDerive(_)
            | CkAttribute::CkaEncrypt(_)
            | CkAttribute::CkaExtractable(_)
            | CkAttribute::CkaModifiable(_)
            | CkAttribute::CkaPrivate(_)
            | CkAttribute::CkaSensitive(_)
            | CkAttribute::CkaSign(_)
            | CkAttribute::CkaSignRecover(_)
            | CkAttribute::CkaToken(_)
            | CkAttribute::CkaUnwrap(_)
            | CkAttribute::CkaVerify(_)
            | CkAttribute::CkaVerifyRecover(_)
            | CkAttribute::CkaWrap(_) => std::mem::size_of::<CK_BBOOL>(),
            CkAttribute::CkaBase(_) => std::mem::size_of::<CK_BYTE>(),
            CkAttribute::CkaClass(_) => std::mem::size_of::<CK_OBJECT_CLASS>(),
            CkAttribute::CkaKeyType(_) => std::mem::size_of::<CK_KEY_TYPE>(),
            CkAttribute::CkaLabel(label) => std::mem::size_of::<CK_UTF8CHAR>() * label.len(),
            CkAttribute::CkaModulusBits(_) => std::mem::size_of::<CK_ULONG>(),
            CkAttribute::CkaPrime(bytes) => std::mem::size_of::<CK_BYTE>() * bytes.len(),
            CkAttribute::CkaPublicExponent(bytes) => std::mem::size_of::<CK_BYTE>() * bytes.len(),
            CkAttribute::CkaValue(bytes) => std::mem::size_of::<u8>() * bytes.len(),
            CkAttribute::CkaValueLen(_) => std::mem::size_of::<CK_ULONG>(),
        };
        len.try_into().unwrap()
    }

    /// Returns a CK_VOID_PTR pointing to the object contained by this CkAttribute.
    fn get_attribute_ptr(&mut self) -> CK_VOID_PTR {
        match self {
            CkAttribute::CkaCopyable(b)
            | CkAttribute::CkaDecrypt(b)
            | CkAttribute::CkaDerive(b)
            | CkAttribute::CkaEncrypt(b)
            | CkAttribute::CkaExtractable(b)
            | CkAttribute::CkaModifiable(b)
            | CkAttribute::CkaPrivate(b)
            | CkAttribute::CkaSensitive(b)
            | CkAttribute::CkaSign(b)
            | CkAttribute::CkaSignRecover(b)
            | CkAttribute::CkaToken(b)
            | CkAttribute::CkaUnwrap(b)
            | CkAttribute::CkaVerify(b)
            | CkAttribute::CkaVerifyRecover(b)
            | CkAttribute::CkaWrap(b) => {
                let b_ptr = *b as *mut _ as CK_VOID_PTR;
                b_ptr
            }
            CkAttribute::CkaBase(byte) => {
                let byte_ptr = *byte as *mut _ as CK_VOID_PTR;
                byte_ptr
            }
            CkAttribute::CkaClass(object_class) => {
                let object_class_ptr = *object_class as CK_OBJECT_CLASS_PTR as CK_VOID_PTR;
                object_class_ptr
            }
            CkAttribute::CkaKeyType(key_type) => {
                let key_type_ptr = *key_type as *mut _ as CK_VOID_PTR;
                key_type_ptr
            }
            CkAttribute::CkaLabel(label) => {
                let label_ptr = label.as_ptr() as CK_VOID_PTR;
                label_ptr
            }
            CkAttribute::CkaModulusBits(bits) => {
                let bits_ptr = *bits as *mut _ as CK_VOID_PTR;
                bits_ptr
            }
            CkAttribute::CkaPrime(bytes) => {
                let bytes_ptr = bytes.as_ptr() as CK_VOID_PTR;
                bytes_ptr
            }
            CkAttribute::CkaPublicExponent(bytes) => {
                let bytes_ptr = bytes.as_ptr() as CK_VOID_PTR;
                bytes_ptr
            }
            CkAttribute::CkaValue(value) => {
                let value_ptr = value.as_ptr() as CK_VOID_PTR;
                value_ptr
            }
            CkAttribute::CkaValueLen(len) => {
                let len_ptr = *len as *mut _ as CK_VOID_PTR;
                len_ptr
            }
        }
    }
}

impl From<&mut CkAttribute<'_>> for CK_ATTRIBUTE {
    fn from(ck_attribute: &mut CkAttribute) -> Self {
        Self {
            type_: ck_attribute.get_attribute_type().into(),
            pValue: ck_attribute.get_attribute_ptr(),
            ulValueLen: ck_attribute.get_attribute_len(),
        }
    }
}

/* NOTE: The newtypes in this module are manual expansions of variants
 * of [CK_UTF8CHAR; N].
 * A future version of this library should replace these with PaddingStr<N>
 * for const N, once Rust stablizes the constant generics feature.
 */
pub mod padding {
    use super::{CK_CHAR, CK_UTF8CHAR};
    use crate::str_from_blank_padded;

    /// Encapsulates a blank-padded 16-byte UTF-8 string for conversion purposes.
    #[derive(Copy, Clone)]
    #[repr(transparent)]
    pub struct BlankPaddedString16(pub [CK_CHAR; 16]);

    impl std::convert::From<BlankPaddedString16> for String {
        fn from(field: BlankPaddedString16) -> String {
            str_from_blank_padded(&field.0)
        }
    }

    impl Default for BlankPaddedString16 {
        fn default() -> Self {
            Self { 0: [32; 16] }
        }
    }

    impl std::fmt::Display for BlankPaddedString16 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
            write!(f, "{}", String::from(*self))
        }
    }

    impl std::fmt::Debug for BlankPaddedString16 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
            write!(f, "CK_CHAR \"{}\"", String::from_utf8_lossy(&self.0))
        }
    }

    /// Encapsulates a blank-padded 16-byte UTF-8 string for conversion purposes.
    #[derive(Copy, Clone)]
    #[repr(transparent)]
    pub struct BlankPaddedUtf8String16(pub [CK_UTF8CHAR; 16]);

    impl std::convert::From<BlankPaddedUtf8String16> for String {
        fn from(field: BlankPaddedUtf8String16) -> String {
            str_from_blank_padded(&field.0)
        }
    }

    impl Default for BlankPaddedUtf8String16 {
        fn default() -> Self {
            Self { 0: [32; 16] }
        }
    }

    impl std::fmt::Display for BlankPaddedUtf8String16 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
            write!(f, "{}", String::from(*self))
        }
    }

    impl std::fmt::Debug for BlankPaddedUtf8String16 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
            write!(f, "CK_UTF8CHAR \"{}\"", String::from_utf8_lossy(&self.0))
        }
    }

    /// Encapsulates a blank-padded 32-byte UTF-8 string for conversion purposes.
    #[derive(Copy, Clone)]
    #[repr(transparent)]
    pub struct BlankPaddedUtf8String32(pub [CK_UTF8CHAR; 32]);

    impl std::convert::From<BlankPaddedUtf8String32> for String {
        fn from(field: BlankPaddedUtf8String32) -> String {
            str_from_blank_padded(&field.0)
        }
    }

    impl Default for BlankPaddedUtf8String32 {
        fn default() -> Self {
            Self { 0: [32; 32] }
        }
    }

    impl std::fmt::Display for BlankPaddedUtf8String32 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
            write!(f, "{}", String::from(*self))
        }
    }

    impl std::fmt::Debug for BlankPaddedUtf8String32 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
            write!(f, "CK_UTF8CHAR \"{}\"", String::from_utf8_lossy(&self.0))
        }
    }

    /// Encapsulates a blank-padded 64-byte UTF-8 string for conversion purposes.
    #[derive(Copy, Clone)]
    #[repr(transparent)]
    pub struct BlankPaddedUtf8String64(pub [CK_UTF8CHAR; 64]);

    impl std::convert::From<BlankPaddedUtf8String64> for String {
        fn from(field: BlankPaddedUtf8String64) -> String {
            str_from_blank_padded(&field.0)
        }
    }

    impl Default for BlankPaddedUtf8String64 {
        fn default() -> Self {
            Self { 0: [32; 64] }
        }
    }

    impl std::fmt::Display for BlankPaddedUtf8String64 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
            write!(f, "{}", String::from(*self))
        }
    }

    impl std::fmt::Debug for BlankPaddedUtf8String64 {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
            write!(f, "CK_UTF8CHAR \"{}\"", String::from_utf8_lossy(&self.0))
        }
    }
}
