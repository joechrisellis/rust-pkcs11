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
#![allow(non_camel_case_types, non_snake_case, clippy::unreadable_literal)]

pub mod types;

use crate::types::{CkAttribute, CkAttributeType, CkCInitializeArgs};
use pkcs11_sys::*;
extern crate num_bigint;

#[cfg(test)]
#[macro_use]
extern crate serial_test_derive;

#[cfg(test)]
mod tests;

/// The error types are defined here - they are used throughout the crate.
pub mod errors;

use errors::Error;

use std::ffi::CString;
use std::mem;
use std::path::Path;
use std::ptr;

trait CkFrom<T> {
    fn from(_: T) -> Self;
}

impl CkFrom<bool> for CK_BBOOL {
    fn from(b: bool) -> Self {
        if b {
            1
        } else {
            0
        }
    }
}

impl CkFrom<CK_BBOOL> for bool {
    fn from(b: CK_BBOOL) -> bool {
        match b {
            0 => false,
            _ => true,
        }
    }
}

fn str_from_blank_padded(field: &[CK_UTF8CHAR]) -> String {
    let decoded_str = String::from_utf8_lossy(field);
    decoded_str.trim_end_matches(' ').to_string()
}

fn label_from_str(label: &str) -> [CK_UTF8CHAR; 32] {
    // initialize a fixed-size array with whitespace characters
    let mut lab: [CK_UTF8CHAR; 32] = [32; 32];
    let mut i = 0;
    for c in label.chars() {
        if i + c.len_utf8() <= 32 {
            let mut buf = [0; 4];
            let bytes = c.encode_utf8(&mut buf).as_bytes();
            for b in bytes {
                lab[i] = *b;
                i += 1;
            }
        } else {
            break;
        }
    }
    lab
}

#[allow(dead_code)]
pub struct Ctx {
    pkcs11_lib: Pkcs11,
    _is_initialized: bool,
    version: CK_VERSION,
    C_Initialize: CK_C_Initialize,
    C_Finalize: CK_C_Finalize,
    C_GetInfo: CK_C_GetInfo,
    C_GetFunctionList: CK_C_GetFunctionList,
    C_GetSlotList: CK_C_GetSlotList,
    C_GetSlotInfo: CK_C_GetSlotInfo,
    C_GetTokenInfo: CK_C_GetTokenInfo,
    C_GetMechanismList: CK_C_GetMechanismList,
    C_GetMechanismInfo: CK_C_GetMechanismInfo,
    C_InitToken: CK_C_InitToken,
    C_InitPIN: CK_C_InitPIN,
    C_SetPIN: CK_C_SetPIN,
    C_OpenSession: CK_C_OpenSession,
    C_CloseSession: CK_C_CloseSession,
    C_CloseAllSessions: CK_C_CloseAllSessions,
    C_GetSessionInfo: CK_C_GetSessionInfo,
    C_GetOperationState: CK_C_GetOperationState,
    C_SetOperationState: CK_C_SetOperationState,
    C_Login: CK_C_Login,
    C_Logout: CK_C_Logout,
    C_CreateObject: CK_C_CreateObject,
    C_CopyObject: CK_C_CopyObject,
    C_DestroyObject: CK_C_DestroyObject,
    C_GetObjectSize: CK_C_GetObjectSize,
    C_GetAttributeValue: CK_C_GetAttributeValue,
    C_SetAttributeValue: CK_C_SetAttributeValue,
    C_FindObjectsInit: CK_C_FindObjectsInit,
    C_FindObjects: CK_C_FindObjects,
    C_FindObjectsFinal: CK_C_FindObjectsFinal,
    C_EncryptInit: CK_C_EncryptInit,
    C_Encrypt: CK_C_Encrypt,
    C_EncryptUpdate: CK_C_EncryptUpdate,
    C_EncryptFinal: CK_C_EncryptFinal,
    C_DecryptInit: CK_C_DecryptInit,
    C_Decrypt: CK_C_Decrypt,
    C_DecryptUpdate: CK_C_DecryptUpdate,
    C_DecryptFinal: CK_C_DecryptFinal,
    C_DigestInit: CK_C_DigestInit,
    C_Digest: CK_C_Digest,
    C_DigestUpdate: CK_C_DigestUpdate,
    C_DigestKey: CK_C_DigestKey,
    C_DigestFinal: CK_C_DigestFinal,
    C_SignInit: CK_C_SignInit,
    C_Sign: CK_C_Sign,
    C_SignUpdate: CK_C_SignUpdate,
    C_SignFinal: CK_C_SignFinal,
    C_SignRecoverInit: CK_C_SignRecoverInit,
    C_SignRecover: CK_C_SignRecover,
    C_VerifyInit: CK_C_VerifyInit,
    C_Verify: CK_C_Verify,
    C_VerifyUpdate: CK_C_VerifyUpdate,
    C_VerifyFinal: CK_C_VerifyFinal,
    C_VerifyRecoverInit: CK_C_VerifyRecoverInit,
    C_VerifyRecover: CK_C_VerifyRecover,
    C_DigestEncryptUpdate: CK_C_DigestEncryptUpdate,
    C_DecryptDigestUpdate: CK_C_DecryptDigestUpdate,
    C_SignEncryptUpdate: CK_C_SignEncryptUpdate,
    C_DecryptVerifyUpdate: CK_C_DecryptVerifyUpdate,
    C_GenerateKey: CK_C_GenerateKey,
    C_GenerateKeyPair: CK_C_GenerateKeyPair,
    C_WrapKey: CK_C_WrapKey,
    C_UnwrapKey: CK_C_UnwrapKey,
    C_DeriveKey: CK_C_DeriveKey,
    C_SeedRandom: CK_C_SeedRandom,
    C_GenerateRandom: CK_C_GenerateRandom,
    C_GetFunctionStatus: CK_C_GetFunctionStatus,
    C_CancelFunction: CK_C_CancelFunction,
    // Functions added in for Cryptoki Version 2.01 or later
    C_WaitForSlotEvent: CK_C_WaitForSlotEvent,
}

impl Ctx {
    pub fn new<P>(filename: P) -> Result<Ctx, Error>
    where
        P: AsRef<Path>,
    {
        unsafe {
            let pkcs11_lib =
                Pkcs11::new(filename.as_ref()).map_err(|e| Error::LibraryLoading { err: e })?;
            let mut list = mem::MaybeUninit::uninit();
            // pkcs11_lib
            // .can_call()
            // .C_GetFunctionList()
            // .map_err(|e| Error::LibraryLoading { err: e })?;

            match pkcs11_lib.C_GetFunctionList(list.as_mut_ptr()) {
                CKR_OK => (),
                err => return Err(Error::Pkcs11(err)),
            }

            let list_ptr = *list.as_ptr();

            Ok(Ctx {
                pkcs11_lib,
                _is_initialized: false,
                version: (*list_ptr).version,
                C_Initialize: Some(
                    (*list_ptr)
                        .C_Initialize
                        .ok_or(Error::Module("C_Initialize function not found"))?,
                ),
                C_Finalize: Some(
                    (*list_ptr)
                        .C_Finalize
                        .ok_or(Error::Module("C_Finalize function not found"))?,
                ),
                C_GetInfo: Some(
                    (*list_ptr)
                        .C_GetInfo
                        .ok_or(Error::Module("C_GetInfo function not found"))?,
                ),
                C_GetFunctionList: Some(
                    (*list_ptr)
                        .C_GetFunctionList
                        .ok_or(Error::Module("C_GetFunctionList function not found"))?,
                ),
                C_GetSlotList: Some(
                    (*list_ptr)
                        .C_GetSlotList
                        .ok_or(Error::Module("C_GetSlotList function not found"))?,
                ),
                C_GetSlotInfo: Some(
                    (*list_ptr)
                        .C_GetSlotInfo
                        .ok_or(Error::Module("C_GetSlotInfo function not found"))?,
                ),
                C_GetTokenInfo: Some(
                    (*list_ptr)
                        .C_GetTokenInfo
                        .ok_or(Error::Module("C_GetTokenInfo function not found"))?,
                ),
                C_GetMechanismList: Some(
                    (*list_ptr)
                        .C_GetMechanismList
                        .ok_or(Error::Module("C_GetMechanismList function not found"))?,
                ),
                C_GetMechanismInfo: Some(
                    (*list_ptr)
                        .C_GetMechanismInfo
                        .ok_or(Error::Module("C_GetMechanismInfo function not found"))?,
                ),
                C_InitToken: Some(
                    (*list_ptr)
                        .C_InitToken
                        .ok_or(Error::Module("C_InitToken function not found"))?,
                ),
                C_InitPIN: Some(
                    (*list_ptr)
                        .C_InitPIN
                        .ok_or(Error::Module("C_InitPIN function not found"))?,
                ),
                C_SetPIN: Some(
                    (*list_ptr)
                        .C_SetPIN
                        .ok_or(Error::Module("C_SetPIN function not found"))?,
                ),
                C_OpenSession: Some(
                    (*list_ptr)
                        .C_OpenSession
                        .ok_or(Error::Module("C_OpenSession function not found"))?,
                ),
                C_CloseSession: Some(
                    (*list_ptr)
                        .C_CloseSession
                        .ok_or(Error::Module("C_CloseSession function not found"))?,
                ),
                C_CloseAllSessions: Some(
                    (*list_ptr)
                        .C_CloseAllSessions
                        .ok_or(Error::Module("C_CloseAllSessions function not found"))?,
                ),
                C_GetSessionInfo: Some(
                    (*list_ptr)
                        .C_GetSessionInfo
                        .ok_or(Error::Module("C_GetSessionInfo function not found"))?,
                ),
                C_GetOperationState: Some(
                    (*list_ptr)
                        .C_GetOperationState
                        .ok_or(Error::Module("C_GetOperationState function not found"))?,
                ),
                C_SetOperationState: Some(
                    (*list_ptr)
                        .C_SetOperationState
                        .ok_or(Error::Module("C_SetOperationState function not found"))?,
                ),
                C_Login: Some(
                    (*list_ptr)
                        .C_Login
                        .ok_or(Error::Module("C_Login function not found"))?,
                ),
                C_Logout: Some(
                    (*list_ptr)
                        .C_Logout
                        .ok_or(Error::Module("C_Logout function not found"))?,
                ),
                C_CreateObject: Some(
                    (*list_ptr)
                        .C_CreateObject
                        .ok_or(Error::Module("C_CreateObject function not found"))?,
                ),
                C_CopyObject: Some(
                    (*list_ptr)
                        .C_CopyObject
                        .ok_or(Error::Module("C_CopyObject function not found"))?,
                ),
                C_DestroyObject: Some(
                    (*list_ptr)
                        .C_DestroyObject
                        .ok_or(Error::Module("C_DestroyObject function not found"))?,
                ),
                C_GetObjectSize: Some(
                    (*list_ptr)
                        .C_GetObjectSize
                        .ok_or(Error::Module("C_GetObjectSize function not found"))?,
                ),
                C_GetAttributeValue: Some(
                    (*list_ptr)
                        .C_GetAttributeValue
                        .ok_or(Error::Module("C_GetAttributeValue function not found"))?,
                ),
                C_SetAttributeValue: Some(
                    (*list_ptr)
                        .C_SetAttributeValue
                        .ok_or(Error::Module("C_SetAttributeValue function not found"))?,
                ),
                C_FindObjectsInit: Some(
                    (*list_ptr)
                        .C_FindObjectsInit
                        .ok_or(Error::Module("C_FindObjectsInit function not found"))?,
                ),
                C_FindObjects: Some(
                    (*list_ptr)
                        .C_FindObjects
                        .ok_or(Error::Module("C_FindObjects function not found"))?,
                ),
                C_FindObjectsFinal: Some(
                    (*list_ptr)
                        .C_FindObjectsFinal
                        .ok_or(Error::Module("C_FindObjectsFinal function not found"))?,
                ),
                C_EncryptInit: Some(
                    (*list_ptr)
                        .C_EncryptInit
                        .ok_or(Error::Module("C_EncryptInit function not found"))?,
                ),
                C_Encrypt: Some(
                    (*list_ptr)
                        .C_Encrypt
                        .ok_or(Error::Module("C_Encrypt function not found"))?,
                ),
                C_EncryptUpdate: Some(
                    (*list_ptr)
                        .C_EncryptUpdate
                        .ok_or(Error::Module("C_EncryptUpdate function not found"))?,
                ),
                C_EncryptFinal: Some(
                    (*list_ptr)
                        .C_EncryptFinal
                        .ok_or(Error::Module("C_EncryptFinal function not found"))?,
                ),
                C_DecryptInit: Some(
                    (*list_ptr)
                        .C_DecryptInit
                        .ok_or(Error::Module("C_DecryptInit function not found"))?,
                ),
                C_Decrypt: Some(
                    (*list_ptr)
                        .C_Decrypt
                        .ok_or(Error::Module("C_Decrypt function not found"))?,
                ),
                C_DecryptUpdate: Some(
                    (*list_ptr)
                        .C_DecryptUpdate
                        .ok_or(Error::Module("C_DecryptUpdate function not found"))?,
                ),
                C_DecryptFinal: Some(
                    (*list_ptr)
                        .C_DecryptFinal
                        .ok_or(Error::Module("C_DecryptFinal function not found"))?,
                ),
                C_DigestInit: Some(
                    (*list_ptr)
                        .C_DigestInit
                        .ok_or(Error::Module("C_DigestInit function not found"))?,
                ),
                C_Digest: Some(
                    (*list_ptr)
                        .C_Digest
                        .ok_or(Error::Module("C_Digest function not found"))?,
                ),
                C_DigestUpdate: Some(
                    (*list_ptr)
                        .C_DigestUpdate
                        .ok_or(Error::Module("C_DigestUpdate function not found"))?,
                ),
                C_DigestKey: Some(
                    (*list_ptr)
                        .C_DigestKey
                        .ok_or(Error::Module("C_DigestKey function not found"))?,
                ),
                C_DigestFinal: Some(
                    (*list_ptr)
                        .C_DigestFinal
                        .ok_or(Error::Module("C_DigestFinal function not found"))?,
                ),
                C_SignInit: Some(
                    (*list_ptr)
                        .C_SignInit
                        .ok_or(Error::Module("C_SignInit function not found"))?,
                ),
                C_Sign: Some(
                    (*list_ptr)
                        .C_Sign
                        .ok_or(Error::Module("C_Sign function not found"))?,
                ),
                C_SignUpdate: Some(
                    (*list_ptr)
                        .C_SignUpdate
                        .ok_or(Error::Module("C_SignUpdate function not found"))?,
                ),
                C_SignFinal: Some(
                    (*list_ptr)
                        .C_SignFinal
                        .ok_or(Error::Module("C_SignFinal function not found"))?,
                ),
                C_SignRecoverInit: Some(
                    (*list_ptr)
                        .C_SignRecoverInit
                        .ok_or(Error::Module("C_SignRecoverInit function not found"))?,
                ),
                C_SignRecover: Some(
                    (*list_ptr)
                        .C_SignRecover
                        .ok_or(Error::Module("C_SignRecover function not found"))?,
                ),
                C_VerifyInit: Some(
                    (*list_ptr)
                        .C_VerifyInit
                        .ok_or(Error::Module("C_VerifyInit function not found"))?,
                ),
                C_Verify: Some(
                    (*list_ptr)
                        .C_Verify
                        .ok_or(Error::Module("C_Verify function not found"))?,
                ),
                C_VerifyUpdate: Some(
                    (*list_ptr)
                        .C_VerifyUpdate
                        .ok_or(Error::Module("C_VerifyUpdate function not found"))?,
                ),
                C_VerifyFinal: Some(
                    (*list_ptr)
                        .C_VerifyFinal
                        .ok_or(Error::Module("C_VerifyFinal function not found"))?,
                ),
                C_VerifyRecoverInit: Some(
                    (*list_ptr)
                        .C_VerifyRecoverInit
                        .ok_or(Error::Module("C_VerifyRecoverInit function not found"))?,
                ),
                C_VerifyRecover: Some(
                    (*list_ptr)
                        .C_VerifyRecover
                        .ok_or(Error::Module("C_VerifyRecover function not found"))?,
                ),
                C_DigestEncryptUpdate: Some(
                    (*list_ptr)
                        .C_DigestEncryptUpdate
                        .ok_or(Error::Module("C_DigestEncryptUpdate function not found"))?,
                ),
                C_DecryptDigestUpdate: Some(
                    (*list_ptr)
                        .C_DecryptDigestUpdate
                        .ok_or(Error::Module("C_DecryptDigestUpdate function not found"))?,
                ),
                C_SignEncryptUpdate: Some(
                    (*list_ptr)
                        .C_SignEncryptUpdate
                        .ok_or(Error::Module("C_SignEncryptUpdate function not found"))?,
                ),
                C_DecryptVerifyUpdate: Some(
                    (*list_ptr)
                        .C_DecryptVerifyUpdate
                        .ok_or(Error::Module("C_DecryptVerifyUpdate function not found"))?,
                ),
                C_GenerateKey: Some(
                    (*list_ptr)
                        .C_GenerateKey
                        .ok_or(Error::Module("C_GenerateKey function not found"))?,
                ),
                C_GenerateKeyPair: Some(
                    (*list_ptr)
                        .C_GenerateKeyPair
                        .ok_or(Error::Module("C_GenerateKeyPair function not found"))?,
                ),
                C_WrapKey: Some(
                    (*list_ptr)
                        .C_WrapKey
                        .ok_or(Error::Module("C_WrapKey function not found"))?,
                ),
                C_UnwrapKey: Some(
                    (*list_ptr)
                        .C_UnwrapKey
                        .ok_or(Error::Module("C_UnwrapKey function not found"))?,
                ),
                C_DeriveKey: Some(
                    (*list_ptr)
                        .C_DeriveKey
                        .ok_or(Error::Module("C_DeriveKey function not found"))?,
                ),
                C_SeedRandom: Some(
                    (*list_ptr)
                        .C_SeedRandom
                        .ok_or(Error::Module("C_SeedRandom function not found"))?,
                ),
                C_GenerateRandom: Some(
                    (*list_ptr)
                        .C_GenerateRandom
                        .ok_or(Error::Module("C_GenerateRandom function not found"))?,
                ),
                C_GetFunctionStatus: Some(
                    (*list_ptr)
                        .C_GetFunctionStatus
                        .ok_or(Error::Module("C_GetFunctionStatus function not found"))?,
                ),
                C_CancelFunction: Some(
                    (*list_ptr)
                        .C_CancelFunction
                        .ok_or(Error::Module("C_CancelFunction function not found"))?,
                ),
                // Functions added in for Cryptoki Version 2.01 or later:
                // to be compatible with PKCS#11 2.00 we do not fail during initialization
                // but when the function will be called.
                C_WaitForSlotEvent: (*list_ptr).C_WaitForSlotEvent,
            })
        }
    }

    pub fn new_and_initialize<P>(filename: P) -> Result<Ctx, Error>
    where
        P: AsRef<Path>,
    {
        let mut ctx = Ctx::new(filename)?;
        ctx.initialize(CkCInitializeArgs::NoThreads)?;
        Ok(ctx)
    }

    pub fn is_initialized(&self) -> bool {
        self._is_initialized
    }

    fn initialized(&self) -> Result<(), Error> {
        if !self._is_initialized {
            Err(Error::Module("module not initialized"))
        } else {
            Ok(())
        }
    }

    fn not_initialized(&self) -> Result<(), Error> {
        if self._is_initialized {
            Err(Error::Module("module already initialized"))
        } else {
            Ok(())
        }
    }

    pub fn initialize(&mut self, init_args: CkCInitializeArgs) -> Result<(), Error> {
        self.not_initialized()?;
        // if no args are specified, library expects NULL
        let mut init_args = CK_C_INITIALIZE_ARGS::from(init_args);
        let init_args_ptr = &mut init_args;
        match unsafe {
            (self.C_Initialize.unwrap())(
                init_args_ptr as *mut CK_C_INITIALIZE_ARGS as *mut ::std::ffi::c_void,
            )
        } {
            CKR_OK => {
                self._is_initialized = true;
                Ok(())
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn finalize(&mut self) -> Result<(), Error> {
        self.initialized()?;
        match unsafe { (self.C_Finalize.unwrap())(ptr::null_mut()) } {
            CKR_OK => {
                self._is_initialized = false;
                Ok(())
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_info(&self) -> Result<CK_INFO, Error> {
        self.initialized()?;
        let mut info = CK_INFO::default();
        match unsafe { (self.C_GetInfo.unwrap())(&mut info) } {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_function_list(&self) -> Result<CK_FUNCTION_LIST, Error> {
        let mut list = mem::MaybeUninit::uninit();
        match unsafe { (self.C_GetFunctionList.unwrap())(&mut list.as_mut_ptr()) } {
            CKR_OK => unsafe { Ok(*list.as_ptr()) },
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_slot_list(&self, token_present: bool) -> Result<Vec<CK_SLOT_ID>, Error> {
        self.initialized()?;
        let mut slots_len: CK_ULONG = 0;
        match unsafe {
            (self.C_GetSlotList.unwrap())(
                CkFrom::from(token_present),
                ptr::null_mut(),
                &mut slots_len,
            )
        } {
            CKR_OK => {
                // now slots_len contains the number of slots,
                // and we can generate a vector with the right capacity
                // important is to pass slots_len **again** because in
                // the 2nd call it is used to tell C how big the memory
                // in slots is.
                let mut slots = Vec::<CK_SLOT_ID>::with_capacity(slots_len as usize);
                let slots_ptr = slots.as_mut_ptr();
                match unsafe {
                    (self.C_GetSlotList.unwrap())(
                        CkFrom::from(token_present),
                        slots_ptr,
                        &mut slots_len,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            slots.set_len(slots_len as usize);
                        }
                        Ok(slots)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_slot_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_SLOT_INFO, Error> {
        self.initialized()?;
        let mut info: CK_SLOT_INFO = Default::default();
        match unsafe { (self.C_GetSlotInfo.unwrap())(slot_id, &mut info) } {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_token_info(&self, slot_id: CK_SLOT_ID) -> Result<CK_TOKEN_INFO, Error> {
        self.initialized()?;
        let mut info: CK_TOKEN_INFO = Default::default();
        match unsafe { (self.C_GetTokenInfo.unwrap())(slot_id, &mut info) } {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_mechanism_list(&self, slot_id: CK_SLOT_ID) -> Result<Vec<CK_MECHANISM_TYPE>, Error> {
        self.initialized()?;
        let mut count: CK_ULONG = 0;
        match unsafe { (self.C_GetMechanismList.unwrap())(slot_id, ptr::null_mut(), &mut count) } {
            CKR_OK => {
                // see get_slot_list() for an explanation - it works the same way
                let mut list = Vec::<CK_MECHANISM_TYPE>::with_capacity(count as usize);
                let list_ptr = list.as_mut_ptr();
                match unsafe { (self.C_GetMechanismList.unwrap())(slot_id, list_ptr, &mut count) } {
                    CKR_OK => {
                        unsafe {
                            list.set_len(count as usize);
                        }
                        Ok(list)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_mechanism_info(
        &self,
        slot_id: CK_SLOT_ID,
        mechanism_type: CK_MECHANISM_TYPE,
    ) -> Result<CK_MECHANISM_INFO, Error> {
        self.initialized()?;
        let mut info: CK_MECHANISM_INFO = Default::default();
        match unsafe { (self.C_GetMechanismInfo.unwrap())(slot_id, mechanism_type, &mut info) } {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn init_token<'a, 'b>(
        &self,
        slot_id: CK_SLOT_ID,
        pin: Option<&'a str>,
        label: &'b str,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut formatted_label = label_from_str(label).to_vec();
        let formatted_label_ptr = formatted_label.as_mut_ptr();
        match pin {
            Some(pin) => {
                if let Ok(cpin) = CString::new(pin) {
                    let mut cpin_bytes = cpin.into_bytes();
                    match unsafe {
                        (self.C_InitToken.unwrap())(
                            slot_id,
                            cpin_bytes.as_mut_ptr(),
                            cpin_bytes.len() as CK_ULONG,
                            formatted_label_ptr,
                        )
                    } {
                        CKR_OK => Ok(()),
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Err(Error::InvalidInput("PIN contains a nul byte"))
                }
            }
            None => {
                // CKF_PROTECTED_AUTHENTICATION_PATH requires a NULL pointer
                match unsafe {
                    (self.C_InitToken.unwrap())(slot_id, ptr::null_mut(), 0, formatted_label_ptr)
                } {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            }
        }
    }

    pub fn init_pin<'a>(
        &self,
        session: CK_SESSION_HANDLE,
        pin: Option<&'a str>,
    ) -> Result<(), Error> {
        self.initialized()?;
        match pin {
            Some(pin) => {
                if let Ok(cpin) = CString::new(pin) {
                    let mut cpin_bytes = cpin.into_bytes();
                    match unsafe {
                        (self.C_InitPIN.unwrap())(
                            session,
                            cpin_bytes.as_mut_ptr(),
                            cpin_bytes.len() as CK_ULONG,
                        )
                    } {
                        CKR_OK => Ok(()),
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Err(Error::InvalidInput("PIN contains a nul byte"))
                }
            }
            None => match unsafe { (self.C_InitPIN.unwrap())(session, ptr::null_mut(), 0) } {
                CKR_OK => Ok(()),
                err => Err(Error::Pkcs11(err)),
            },
        }
    }

    pub fn set_pin<'a, 'b>(
        &self,
        session: CK_SESSION_HANDLE,
        old_pin: Option<&'a str>,
        new_pin: Option<&'b str>,
    ) -> Result<(), Error> {
        self.initialized()?;
        if old_pin.is_none() && new_pin.is_none() {
            match unsafe {
                (self.C_SetPIN.unwrap())(session, ptr::null_mut(), 0, ptr::null_mut(), 0)
            } {
                CKR_OK => Ok(()),
                err => Err(Error::Pkcs11(err)),
            }
        } else if old_pin.is_some() && new_pin.is_some() {
            let old_cpin_res = CString::new(old_pin.unwrap());
            let new_cpin_res = CString::new(new_pin.unwrap());
            if old_cpin_res.is_err() {
                return Err(Error::InvalidInput("Old PIN contains a nul byte"));
            }
            if new_cpin_res.is_err() {
                return Err(Error::InvalidInput("New PIN contains a nul byte"));
            }
            let mut old_cpin = old_cpin_res.unwrap().into_bytes();
            let mut new_cpin = new_cpin_res.unwrap().into_bytes();
            match unsafe {
                (self.C_SetPIN.unwrap())(
                    session,
                    old_cpin.as_mut_ptr(),
                    old_cpin.len() as CK_ULONG,
                    new_cpin.as_mut_ptr(),
                    new_cpin.len() as CK_ULONG,
                )
            } {
                CKR_OK => Ok(()),
                err => Err(Error::Pkcs11(err)),
            }
        } else {
            Err(Error::InvalidInput("both PINs must be either set or unset"))
        }
    }

    pub fn open_session(
        &self,
        slot_id: CK_SLOT_ID,
        flags: CK_FLAGS,
        application: Option<CK_VOID_PTR>,
        notify: CK_NOTIFY,
    ) -> Result<CK_SESSION_HANDLE, Error> {
        self.initialized()?;
        let mut session: CK_SESSION_HANDLE = 0;
        match unsafe {
            (self.C_OpenSession.unwrap())(
                slot_id,
                flags,
                application.unwrap_or(ptr::null_mut()),
                notify,
                &mut session,
            )
        } {
            CKR_OK => Ok(session),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn close_session(&self, session: CK_SESSION_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        match unsafe { (self.C_CloseSession.unwrap())(session) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn close_all_sessions(&self, slot_id: CK_SLOT_ID) -> Result<(), Error> {
        self.initialized()?;
        match unsafe { (self.C_CloseAllSessions.unwrap())(slot_id) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_session_info(&self, session: CK_SESSION_HANDLE) -> Result<CK_SESSION_INFO, Error> {
        self.initialized()?;
        let mut info: CK_SESSION_INFO = Default::default();
        match unsafe { (self.C_GetSessionInfo.unwrap())(session, &mut info) } {
            CKR_OK => Ok(info),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_operation_state(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut state_length: CK_ULONG = 0;
        match unsafe {
            (self.C_GetOperationState.unwrap())(session, ptr::null_mut(), &mut state_length)
        } {
            CKR_OK => {
                let mut state: Vec<CK_BYTE> = Vec::with_capacity(state_length as usize);
                let state_ptr = state.as_mut_ptr();
                match unsafe {
                    (self.C_GetOperationState.unwrap())(session, state_ptr, &mut state_length)
                } {
                    CKR_OK => {
                        unsafe {
                            state.set_len(state_length as usize);
                        }
                        Ok(state)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn set_operation_state(
        &self,
        session: CK_SESSION_HANDLE,
        operation_state: Vec<CK_BYTE>,
        encryption_key: Option<CK_OBJECT_HANDLE>,
        authentication_key: Option<CK_OBJECT_HANDLE>,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut operation_state = operation_state;
        match unsafe {
            (self.C_SetOperationState.unwrap())(
                session,
                operation_state.as_mut_ptr(),
                operation_state.len() as CK_ULONG,
                encryption_key.unwrap_or(0),
                authentication_key.unwrap_or(0),
            )
        } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn login<'a>(
        &self,
        session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: Option<&'a str>,
    ) -> Result<(), Error> {
        self.initialized()?;
        match pin {
            Some(pin) => {
                if let Ok(cpin) = CString::new(pin) {
                    let mut cpin_bytes = cpin.into_bytes();
                    match unsafe {
                        (self.C_Login.unwrap())(
                            session,
                            user_type,
                            cpin_bytes.as_mut_ptr(),
                            cpin_bytes.len() as CK_ULONG,
                        )
                    } {
                        CKR_OK => Ok(()),
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Err(Error::InvalidInput("PIN contains a nul byte"))
                }
            }
            None => {
                match unsafe { (self.C_Login.unwrap())(session, user_type, ptr::null_mut(), 0) } {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            }
        }
    }

    /// Some dongle drivers (such as Safenet) allow NUL bytes in PINs, and fail
    /// login if a NUL containing PIN is truncated. Combined with poor PIN gen
    /// algorithms which insert NULs into the PIN, you might need a way to supply
    /// raw bytes for a PIN, instead of converting from a UTF8 string as per spec
    pub fn login_with_raw(
        &self,
        session: CK_SESSION_HANDLE,
        user_type: CK_USER_TYPE,
        pin: Option<&[CK_BYTE]>,
    ) -> Result<(), Error> {
        self.initialized()?;
        match pin {
            Some(pin) => {
                let mut pin = pin.to_vec();
                match unsafe {
                    (self.C_Login.unwrap())(
                        session,
                        user_type,
                        pin.as_mut_ptr(),
                        pin.len() as CK_ULONG,
                    )
                } {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            }
            None => {
                match unsafe { (self.C_Login.unwrap())(session, user_type, ptr::null_mut(), 0) } {
                    CKR_OK => Ok(()),
                    err => Err(Error::Pkcs11(err)),
                }
            }
        }
    }

    pub fn logout(&self, session: CK_SESSION_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        match unsafe { (self.C_Logout.unwrap())(session) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn create_object(
        &self,
        session: CK_SESSION_HANDLE,
        template: &mut [CkAttribute],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(CK_ATTRIBUTE::from).collect();
        let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match unsafe {
            (self.C_CreateObject.unwrap())(
                session,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut oh,
            )
        } {
            CKR_OK => Ok(oh),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn copy_object(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        template: &mut [CkAttribute],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(CK_ATTRIBUTE::from).collect();
        let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match unsafe {
            (self.C_CopyObject.unwrap())(
                session,
                object,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut oh,
            )
        } {
            CKR_OK => Ok(oh),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn destroy_object(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        match unsafe { (self.C_DestroyObject.unwrap())(session, object) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_object_size(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
    ) -> Result<CK_ULONG, Error> {
        self.initialized()?;
        let mut size: CK_ULONG = 0;
        match unsafe { (self.C_GetObjectSize.unwrap())(session, object, &mut size) } {
            CKR_OK => Ok(size),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_attribute_lengths(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        attribute_types: &Vec<CkAttributeType>,
    ) -> Result<Vec<CK_ULONG>, Error> {
        let mut template: Vec<CK_ATTRIBUTE> = attribute_types
            .iter()
            .map(|t| CK_ATTRIBUTE {
                type_: CK_ATTRIBUTE_TYPE::from(*t),
                pValue: ptr::null_mut() as CK_VOID_PTR,
                ulValueLen: 0,
            })
            .collect();

        let res = unsafe {
            (self.C_GetAttributeValue.unwrap())(
                session,
                object,
                template.as_mut_ptr() as *mut pkcs11_sys::CK_ATTRIBUTE,
                template.len() as CK_ULONG,
            )
        };
        let lengths = template
            .iter()
            .map(|ck_attribute| ck_attribute.ulValueLen)
            .collect();
        match res {
            CKR_OK => Ok(lengths),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_attribute_value<'a>(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        template: &'a mut Vec<CkAttribute<'a>>,
    ) -> Result<CK_RV, Error> {
        self.initialized()?;
        /*
          Note that the error codes CKR_ATTRIBUTE_SENSITIVE, CKR_ATTRIBUTE_TYPE_INVALID, and CKR_BUFFER_TOO_SMALL
          do not denote true errors for C_GetAttributeValue.  If a call to C_GetAttributeValue returns any of these three
          values, then the call MUST nonetheless have processed every attribute in the template supplied to
          C_GetAttributeValue.  Each attribute in the template whose value can be returned by the call to
          C_GetAttributeValue will be returned by the call to C_GetAttributeValue.
        */
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(CK_ATTRIBUTE::from).collect();
        let res = unsafe {
            (self.C_GetAttributeValue.unwrap())(
                session,
                object,
                template.as_mut_ptr() as *mut pkcs11_sys::CK_ATTRIBUTE,
                template.len() as CK_ULONG,
            )
        };
        match res {
            CKR_OK => Ok(CKR_OK),
            CKR_ATTRIBUTE_SENSITIVE => Ok(CKR_ATTRIBUTE_SENSITIVE),
            CKR_ATTRIBUTE_TYPE_INVALID => Ok(CKR_ATTRIBUTE_TYPE_INVALID),
            CKR_BUFFER_TOO_SMALL => Ok(CKR_BUFFER_TOO_SMALL),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn set_attribute_value(
        &self,
        session: CK_SESSION_HANDLE,
        object: CK_OBJECT_HANDLE,
        template: &mut [CkAttribute],
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(CK_ATTRIBUTE::from).collect();
        match unsafe {
            (self.C_SetAttributeValue.unwrap())(
                session,
                object,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
            )
        } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn find_objects_init(
        &self,
        session: CK_SESSION_HANDLE,
        template: &mut [CkAttribute],
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(CK_ATTRIBUTE::from).collect();
        match unsafe {
            (self.C_FindObjectsInit.unwrap())(
                session,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
            )
        } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn find_objects(
        &self,
        session: CK_SESSION_HANDLE,
        max_object_count: CK_ULONG,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, Error> {
        self.initialized()?;
        let mut list: Vec<CK_OBJECT_HANDLE> = Vec::with_capacity(max_object_count as usize);
        let mut count: CK_ULONG = 0;
        match unsafe {
            (self.C_FindObjects.unwrap())(session, list.as_mut_ptr(), max_object_count, &mut count)
        } {
            CKR_OK => {
                unsafe {
                    list.set_len(count as usize);
                }
                Ok(list)
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn find_objects_final(&self, session: CK_SESSION_HANDLE) -> Result<(), Error> {
        self.initialized()?;
        match unsafe { (self.C_FindObjectsFinal.unwrap())(session) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn encrypt_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match unsafe { (self.C_EncryptInit.unwrap())(session, &mut mechanism, key) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn encrypt(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut data = data.to_vec();
        let mut encryptedDataLen: CK_ULONG = 0;
        match unsafe {
            (self.C_Encrypt.unwrap())(
                session,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                ptr::null_mut(),
                &mut encryptedDataLen,
            )
        } {
            CKR_OK => {
                let mut encryptedData: Vec<CK_BYTE> = Vec::with_capacity(encryptedDataLen as usize);
                match unsafe {
                    (self.C_Encrypt.unwrap())(
                        session,
                        data.as_mut_ptr(),
                        data.len() as CK_ULONG,
                        encryptedData.as_mut_ptr(),
                        &mut encryptedDataLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            encryptedData.set_len(encryptedDataLen as usize);
                        }
                        Ok(encryptedData)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn encrypt_update(
        &self,
        session: CK_SESSION_HANDLE,
        part: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut part = part.to_vec();
        let mut encryptedPartLen: CK_ULONG = 0;
        match unsafe {
            (self.C_EncryptUpdate.unwrap())(
                session,
                part.as_mut_ptr(),
                part.len() as CK_ULONG,
                ptr::null_mut(),
                &mut encryptedPartLen,
            )
        } {
            CKR_OK => {
                let mut encryptedPart: Vec<CK_BYTE> = Vec::with_capacity(encryptedPartLen as usize);
                match unsafe {
                    (self.C_EncryptUpdate.unwrap())(
                        session,
                        part.as_mut_ptr(),
                        part.len() as CK_ULONG,
                        encryptedPart.as_mut_ptr(),
                        &mut encryptedPartLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            encryptedPart.set_len(encryptedPartLen as usize);
                        }
                        Ok(encryptedPart)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn encrypt_final(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut lastEncryptedPartLen: CK_ULONG = 0;
        match unsafe {
            (self.C_EncryptFinal.unwrap())(session, ptr::null_mut(), &mut lastEncryptedPartLen)
        } {
            CKR_OK => {
                let mut lastEncryptedPart: Vec<CK_BYTE> =
                    Vec::with_capacity(lastEncryptedPartLen as usize);
                match unsafe {
                    (self.C_EncryptFinal.unwrap())(
                        session,
                        lastEncryptedPart.as_mut_ptr(),
                        &mut lastEncryptedPartLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            lastEncryptedPart.set_len(lastEncryptedPartLen as usize);
                        }
                        Ok(lastEncryptedPart)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match unsafe { (self.C_DecryptInit.unwrap())(session, &mut mechanism, key) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt(
        &self,
        session: CK_SESSION_HANDLE,
        encryptedData: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut encrypted_data = encryptedData.to_vec();
        let mut dataLen: CK_ULONG = 0;
        match unsafe {
            (self.C_Decrypt.unwrap())(
                session,
                encrypted_data.as_mut_ptr(),
                encrypted_data.len() as CK_ULONG,
                ptr::null_mut(),
                &mut dataLen,
            )
        } {
            CKR_OK => {
                let mut data: Vec<CK_BYTE> = Vec::with_capacity(dataLen as usize);
                match unsafe {
                    (self.C_Decrypt.unwrap())(
                        session,
                        encrypted_data.as_mut_ptr(),
                        encrypted_data.len() as CK_ULONG,
                        data.as_mut_ptr(),
                        &mut dataLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            data.set_len(dataLen as usize);
                        }
                        Ok(data)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt_update(
        &self,
        session: CK_SESSION_HANDLE,
        encryptedPart: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut encrypted_part = encryptedPart.to_vec();
        let mut partLen: CK_ULONG = 0;
        match unsafe {
            (self.C_DecryptUpdate.unwrap())(
                session,
                encrypted_part.as_mut_ptr(),
                encrypted_part.len() as CK_ULONG,
                ptr::null_mut(),
                &mut partLen,
            )
        } {
            CKR_OK => {
                let mut part: Vec<CK_BYTE> = Vec::with_capacity(partLen as usize);
                match unsafe {
                    (self.C_DecryptUpdate.unwrap())(
                        session,
                        encrypted_part.as_mut_ptr(),
                        encrypted_part.len() as CK_ULONG,
                        part.as_mut_ptr(),
                        &mut partLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            part.set_len(partLen as usize);
                        }
                        Ok(part)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt_final(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut lastPartLen: CK_ULONG = 0;
        match unsafe { (self.C_DecryptFinal.unwrap())(session, ptr::null_mut(), &mut lastPartLen) }
        {
            CKR_OK => {
                let mut lastPart: Vec<CK_BYTE> = Vec::with_capacity(lastPartLen as usize);
                match unsafe {
                    (self.C_DecryptFinal.unwrap())(session, lastPart.as_mut_ptr(), &mut lastPartLen)
                } {
                    CKR_OK => {
                        unsafe {
                            lastPart.set_len(lastPartLen as usize);
                        }
                        Ok(lastPart)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match unsafe { (self.C_DigestInit.unwrap())(session, &mut mechanism) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut data = data.to_vec();
        let mut digestLen: CK_ULONG = 0;
        match unsafe {
            (self.C_Digest.unwrap())(
                session,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                ptr::null_mut(),
                &mut digestLen,
            )
        } {
            CKR_OK => {
                let mut digest: Vec<CK_BYTE> = Vec::with_capacity(digestLen as usize);
                match unsafe {
                    (self.C_Digest.unwrap())(
                        session,
                        data.as_mut_ptr(),
                        data.len() as CK_ULONG,
                        digest.as_mut_ptr(),
                        &mut digestLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            digest.set_len(digestLen as usize);
                        }
                        Ok(digest)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest_update(&self, session: CK_SESSION_HANDLE, part: &[CK_BYTE]) -> Result<(), Error> {
        let mut part = part.to_vec();
        match unsafe {
            (self.C_DigestUpdate.unwrap())(session, part.as_mut_ptr(), part.len() as CK_ULONG)
        } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest_key(
        &self,
        session: CK_SESSION_HANDLE,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        match unsafe { (self.C_DigestKey.unwrap())(session, key) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest_final(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut digestLen: CK_ULONG = 0;
        match unsafe { (self.C_DigestFinal.unwrap())(session, ptr::null_mut(), &mut digestLen) } {
            CKR_OK => {
                let mut digest: Vec<CK_BYTE> = Vec::with_capacity(digestLen as usize);
                match unsafe {
                    (self.C_DigestFinal.unwrap())(session, digest.as_mut_ptr(), &mut digestLen)
                } {
                    CKR_OK => {
                        unsafe {
                            digest.set_len(digestLen as usize);
                        }
                        Ok(digest)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match unsafe { (self.C_SignInit.unwrap())(session, &mut mechanism, key) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut data = data.to_vec();
        let mut signatureLen: CK_ULONG = 0;
        match unsafe {
            (self.C_Sign.unwrap())(
                session,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                ptr::null_mut(),
                &mut signatureLen,
            )
        } {
            CKR_OK => {
                let mut signature: Vec<CK_BYTE> = Vec::with_capacity(signatureLen as usize);
                match unsafe {
                    (self.C_Sign.unwrap())(
                        session,
                        data.as_mut_ptr(),
                        data.len() as CK_ULONG,
                        signature.as_mut_ptr(),
                        &mut signatureLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            signature.set_len(signatureLen as usize);
                        }
                        Ok(signature)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_update(&self, session: CK_SESSION_HANDLE, part: &[CK_BYTE]) -> Result<(), Error> {
        self.initialized()?;
        let mut part = part.to_vec();
        match unsafe {
            (self.C_SignUpdate.unwrap())(session, part.as_mut_ptr(), part.len() as CK_ULONG)
        } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_final(&self, session: CK_SESSION_HANDLE) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut signatureLen: CK_ULONG = 0;
        match unsafe { (self.C_SignFinal.unwrap())(session, ptr::null_mut(), &mut signatureLen) } {
            CKR_OK => {
                let mut signature: Vec<CK_BYTE> = Vec::with_capacity(signatureLen as usize);
                match unsafe {
                    (self.C_SignFinal.unwrap())(session, signature.as_mut_ptr(), &mut signatureLen)
                } {
                    CKR_OK => {
                        unsafe {
                            signature.set_len(signatureLen as usize);
                        }
                        Ok(signature)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_recover_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match unsafe { (self.C_SignRecoverInit.unwrap())(session, &mut mechanism, key) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_recover(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut data = data.to_vec();
        let mut signatureLen: CK_ULONG = 0;
        match unsafe {
            (self.C_SignRecover.unwrap())(
                session,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                ptr::null_mut(),
                &mut signatureLen,
            )
        } {
            CKR_OK => {
                let mut signature: Vec<CK_BYTE> = Vec::with_capacity(signatureLen as usize);
                match unsafe {
                    (self.C_SignRecover.unwrap())(
                        session,
                        data.as_mut_ptr(),
                        data.len() as CK_ULONG,
                        signature.as_mut_ptr(),
                        &mut signatureLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            signature.set_len(signatureLen as usize);
                        }
                        Ok(signature)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match unsafe { (self.C_VerifyInit.unwrap())(session, &mut mechanism, key) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify(
        &self,
        session: CK_SESSION_HANDLE,
        data: &[CK_BYTE],
        signature: &[CK_BYTE],
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut data = data.to_vec();
        let mut signature = signature.to_vec();
        match unsafe {
            (self.C_Verify.unwrap())(
                session,
                data.as_mut_ptr(),
                data.len() as CK_ULONG,
                signature.as_mut_ptr(),
                signature.len() as CK_ULONG,
            )
        } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify_update(&self, session: CK_SESSION_HANDLE, part: &[CK_BYTE]) -> Result<(), Error> {
        self.initialized()?;
        let mut part = part.to_vec();
        match unsafe {
            (self.C_VerifyUpdate.unwrap())(session, part.as_mut_ptr(), part.len() as CK_ULONG)
        } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify_final(
        &self,
        session: CK_SESSION_HANDLE,
        signature: &[CK_BYTE],
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut signature = signature.to_vec();
        match unsafe {
            (self.C_VerifyFinal.unwrap())(
                session,
                signature.as_mut_ptr(),
                signature.len() as CK_ULONG,
            )
        } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify_recover_init(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        key: CK_OBJECT_HANDLE,
    ) -> Result<(), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        match unsafe { (self.C_VerifyRecoverInit.unwrap())(session, &mut mechanism, key) } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn verify_recover(
        &self,
        session: CK_SESSION_HANDLE,
        signature: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut signature = signature.to_vec();
        let mut dataLen: CK_ULONG = 0;
        match unsafe {
            (self.C_VerifyRecover.unwrap())(
                session,
                signature.as_mut_ptr(),
                signature.len() as CK_ULONG,
                ptr::null_mut(),
                &mut dataLen,
            )
        } {
            CKR_OK => {
                let mut data: Vec<CK_BYTE> = Vec::with_capacity(dataLen as usize);
                match unsafe {
                    (self.C_VerifyRecover.unwrap())(
                        session,
                        signature.as_mut_ptr(),
                        signature.len() as CK_ULONG,
                        data.as_mut_ptr(),
                        &mut dataLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            data.set_len(dataLen as usize);
                        }
                        Ok(data)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn digest_encrypt_update(
        &self,
        session: CK_SESSION_HANDLE,
        part: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut part = part.to_vec();
        let mut encryptedPartLen: CK_ULONG = 0;
        match unsafe {
            (self.C_DigestEncryptUpdate.unwrap())(
                session,
                part.as_mut_ptr(),
                part.len() as CK_ULONG,
                ptr::null_mut(),
                &mut encryptedPartLen,
            )
        } {
            CKR_OK => {
                let mut encryptedPart: Vec<CK_BYTE> = Vec::with_capacity(encryptedPartLen as usize);
                match unsafe {
                    (self.C_DigestEncryptUpdate.unwrap())(
                        session,
                        part.as_mut_ptr(),
                        part.len() as CK_ULONG,
                        encryptedPart.as_mut_ptr(),
                        &mut encryptedPartLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            encryptedPart.set_len(encryptedPartLen as usize);
                        }
                        Ok(encryptedPart)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt_digest_update(
        &self,
        session: CK_SESSION_HANDLE,
        encryptedPart: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut encrypted_part = encryptedPart.to_vec();
        let mut partLen: CK_ULONG = 0;
        match unsafe {
            (self.C_DecryptDigestUpdate.unwrap())(
                session,
                encrypted_part.as_mut_ptr(),
                encrypted_part.len() as CK_ULONG,
                ptr::null_mut(),
                &mut partLen,
            )
        } {
            CKR_OK => {
                let mut part: Vec<CK_BYTE> = Vec::with_capacity(partLen as usize);
                match unsafe {
                    (self.C_DecryptDigestUpdate.unwrap())(
                        session,
                        encrypted_part.as_mut_ptr(),
                        encrypted_part.len() as CK_ULONG,
                        part.as_mut_ptr(),
                        &mut partLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            part.set_len(partLen as usize);
                        }
                        Ok(part)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn sign_encrypt_update(
        &self,
        session: CK_SESSION_HANDLE,
        part: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut part = part.to_vec();
        let mut encryptedPartLen: CK_ULONG = 0;
        match unsafe {
            (self.C_SignEncryptUpdate.unwrap())(
                session,
                part.as_mut_ptr(),
                part.len() as CK_ULONG,
                ptr::null_mut(),
                &mut encryptedPartLen,
            )
        } {
            CKR_OK => {
                let mut encryptedPart: Vec<CK_BYTE> = Vec::with_capacity(encryptedPartLen as usize);
                match unsafe {
                    (self.C_SignEncryptUpdate.unwrap())(
                        session,
                        part.as_mut_ptr(),
                        part.len() as CK_ULONG,
                        encryptedPart.as_mut_ptr(),
                        &mut encryptedPartLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            encryptedPart.set_len(encryptedPartLen as usize);
                        }
                        Ok(encryptedPart)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn decrypt_verify_update(
        &self,
        session: CK_SESSION_HANDLE,
        encryptedPart: Vec<CK_BYTE>,
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut encrypted_part = encryptedPart;
        let mut partLen: CK_ULONG = 0;
        match unsafe {
            (self.C_DecryptVerifyUpdate.unwrap())(
                session,
                encrypted_part.as_mut_ptr(),
                encrypted_part.len() as CK_ULONG,
                ptr::null_mut(),
                &mut partLen,
            )
        } {
            CKR_OK => {
                let mut part: Vec<CK_BYTE> = Vec::with_capacity(partLen as usize);
                match unsafe {
                    (self.C_DecryptVerifyUpdate.unwrap())(
                        session,
                        encrypted_part.as_mut_ptr(),
                        encrypted_part.len() as CK_ULONG,
                        part.as_mut_ptr(),
                        &mut partLen,
                    )
                } {
                    CKR_OK => {
                        unsafe {
                            part.set_len(partLen as usize);
                        }
                        Ok(part)
                    }
                    err => Err(Error::Pkcs11(err)),
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn generate_key(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        template: &mut [CkAttribute],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(CK_ATTRIBUTE::from).collect();
        let mut object: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match unsafe {
            (self.C_GenerateKey.unwrap())(
                session,
                &mut mechanism,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut object,
            )
        } {
            CKR_OK => Ok(object),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn generate_key_pair(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        publicKeyTemplate: &mut [CkAttribute],
        privateKeyTemplate: &mut [CkAttribute],
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        let mut public_key_template: Vec<CK_ATTRIBUTE> = publicKeyTemplate
            .iter_mut()
            .map(CK_ATTRIBUTE::from)
            .collect();
        let mut private_key_template: Vec<CK_ATTRIBUTE> = privateKeyTemplate
            .iter_mut()
            .map(CK_ATTRIBUTE::from)
            .collect();
        let mut pubOh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        let mut privOh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match unsafe {
            (self.C_GenerateKeyPair.unwrap())(
                session,
                &mut mechanism,
                public_key_template.as_mut_ptr(),
                public_key_template.len() as CK_ULONG,
                private_key_template.as_mut_ptr(),
                private_key_template.len() as CK_ULONG,
                &mut pubOh,
                &mut privOh,
            )
        } {
            CKR_OK => Ok((pubOh, privOh)),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn wrap_key(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        wrappingKey: CK_OBJECT_HANDLE,
        key: CK_OBJECT_HANDLE,
    ) -> Result<Vec<CK_BYTE>, Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        let mut length: CK_ULONG = 0;
        match unsafe {
            (self.C_WrapKey.unwrap())(
                session,
                &mut mechanism,
                wrappingKey,
                key,
                ptr::null_mut(),
                &mut length,
            )
        } {
            CKR_OK => {
                if length > 0 {
                    let mut out: Vec<CK_BYTE> = Vec::with_capacity(length as usize);
                    match unsafe {
                        (self.C_WrapKey.unwrap())(
                            session,
                            &mut mechanism,
                            wrappingKey,
                            key,
                            out.as_mut_ptr(),
                            &mut length,
                        )
                    } {
                        CKR_OK => {
                            unsafe {
                                out.set_len(length as usize);
                            }
                            Ok(out)
                        }
                        err => Err(Error::Pkcs11(err)),
                    }
                } else {
                    Ok(vec![])
                }
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn unwrap_key(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        unwrappingKey: CK_OBJECT_HANDLE,
        wrappedKey: &[CK_BYTE],
        template: &mut [CkAttribute],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        let mut wrapped_key = wrappedKey.to_vec();
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(CK_ATTRIBUTE::from).collect();
        let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match unsafe {
            (self.C_UnwrapKey.unwrap())(
                session,
                &mut mechanism,
                unwrappingKey,
                wrapped_key.as_mut_ptr(),
                wrapped_key.len() as CK_ULONG,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut oh,
            )
        } {
            CKR_OK => Ok(oh),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn derive_key(
        &self,
        session: CK_SESSION_HANDLE,
        mechanism: &CK_MECHANISM,
        baseKey: CK_OBJECT_HANDLE,
        template: &mut [CkAttribute],
    ) -> Result<CK_OBJECT_HANDLE, Error> {
        self.initialized()?;
        let mut mechanism = *mechanism;
        let mut template: Vec<CK_ATTRIBUTE> = template.iter_mut().map(CK_ATTRIBUTE::from).collect();
        let mut oh: CK_OBJECT_HANDLE = CK_INVALID_HANDLE;
        match unsafe {
            (self.C_DeriveKey.unwrap())(
                session,
                &mut mechanism,
                baseKey,
                template.as_mut_ptr(),
                template.len() as CK_ULONG,
                &mut oh,
            )
        } {
            CKR_OK => Ok(oh),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn seed_random(&self, session: CK_SESSION_HANDLE, seed: &[CK_BYTE]) -> Result<(), Error> {
        let mut seed = seed.to_vec();
        match unsafe {
            (self.C_SeedRandom.unwrap())(session, seed.as_mut_ptr(), seed.len() as CK_ULONG)
        } {
            CKR_OK => Ok(()),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn generate_random(
        &self,
        session: CK_SESSION_HANDLE,
        randomLength: CK_ULONG,
    ) -> Result<Vec<CK_BYTE>, Error> {
        let mut data: Vec<CK_BYTE> = Vec::with_capacity(randomLength as usize);
        match unsafe { (self.C_GenerateRandom.unwrap())(session, data.as_mut_ptr(), randomLength) }
        {
            CKR_OK => {
                unsafe {
                    data.set_len(randomLength as usize);
                }
                Ok(data)
            }
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn get_function_status(&self, session: CK_SESSION_HANDLE) -> Result<CK_RV, Error> {
        match unsafe { (self.C_GetFunctionStatus.unwrap())(session) } {
            CKR_OK => Ok(CKR_OK),
            CKR_FUNCTION_NOT_PARALLEL => Ok(CKR_FUNCTION_NOT_PARALLEL),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn cancel_function(&self, session: CK_SESSION_HANDLE) -> Result<CK_RV, Error> {
        match unsafe { (self.C_CancelFunction.unwrap())(session) } {
            CKR_OK => Ok(CKR_OK),
            CKR_FUNCTION_NOT_PARALLEL => Ok(CKR_FUNCTION_NOT_PARALLEL),
            err => Err(Error::Pkcs11(err)),
        }
    }

    pub fn wait_for_slot_event(&self, flags: CK_FLAGS) -> Result<Option<CK_SLOT_ID>, Error> {
        let mut slotID: CK_SLOT_ID = 0;
        let C_WaitForSlotEvent = self
            .C_WaitForSlotEvent
            .ok_or(Error::Module("C_WaitForSlotEvent function not found"))?;
        match unsafe { C_WaitForSlotEvent(flags, &mut slotID, ptr::null_mut()) } {
            CKR_OK => Ok(Some(slotID)),
            CKR_NO_EVENT => Ok(None),
            err => Err(Error::Pkcs11(err)),
        }
    }
}

impl Drop for Ctx {
    fn drop(&mut self) {
        if self.is_initialized() {
            if let Err(err) = self.finalize() {
                println!("ERROR: {}", err);
            }
        }
    }
}
