use core::starknet::secp256_trait::Signature;
use crate::utils::compare::PartialEqU8Array32;
// EnclaveIdentityV2:
//     type: object
//     description: SGX Enclave Identity data structure encoded as JSON string in case of success
//         (200 HTTP status code)
//     properties:
//         enclaveIdentity:
//             type: object
//             properties:
//                 id:
//                     type: string
//                     description: Identifier of the SGX Enclave issued by Intel. Supported values are QE, QVE and TD_QE
//                 version:
//                     type: integer
//                     example: 2
//                     description: Version of the structure
//                 issueDate:
//                     type: string
//                     format: date-time
//                     description: >-
//                         Representation of date and time the Enclave Identity information
//                         was created. The time shall be in UTC and the encoding shall
//                         be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ)
//                 nextUpdate:
//                     type: string
//                     format: date-time
//                     description: >-
//                         Representation of date and time by which next Enclave Identity
//                         information will be issued. The time shall be in
//                         UTC and the encoding shall be compliant to ISO 8601 standard
//                         (YYYY-MM-DDThh:mm:ssZ)
//                 tcbEvaluationDataNumber:
//                     type: integer
//                     example: 2
//                     description: >-
//                         A monotonically increasing sequence number changed
//                         when Intel updates the content of the TCB evaluation data
//                         set: TCB Info, QE Idenity and QVE Identity. The tcbEvaluationDataNumber
//                         update is synchronized across TCB Info for all flavors of
//                         SGX CPUs (Family-Model-Stepping-Platform-CustomSKU) and QE/QVE
//                         Identity. This sequence number allows users to easily determine
//                         when a particular TCB Info/QE Idenity/QVE Identiy superseedes
//                         another TCB Info/QE Identity/QVE Identity (value: current
//                         TCB Recovery event number stored in the database).
//                 miscselect:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{8}$
//                     example: '00000000'
//                     description: Base 16-encoded string representing miscselect "golden" value (upon applying mask).
//                 miscselectMask:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{8}$
//                     example: '00000000'
//                     description: Base 16-encoded string representing mask to be applied to miscselect value retrieved from the platform.
//                 attributes:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{32}$
//                     example: '00000000000000000000000000000000'
//                     description: Base 16-encoded string representing attributes "golden" value (upon applying mask).
//                 attributesMask:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{32}$
//                     example: '00000000000000000000000000000000'
//                     description: Base 16-encoded string representing mask to be applied to attributes value retrieved from the platform.
//                 mrsigner:
//                     type: string
//                     pattern: ^[0-9a-fA-F]{64}$
//                     example: '0000000000000000000000000000000000000000000000000000000000000000'
//                     description: Base 16-encoded string representing mrsigner hash.
//                 isvprodid:
//                     type: integer
//                     example: 0
//                     minimum: 0
//                     maximum: 65535
//                     description: Enclave Product ID.
//                 tcbLevels:
//                     description: >-
//                         Sorted list of supported Enclave TCB levels for given
//                         QVE encoded as a JSON array of Enclave TCB level objects.
//                     type: array
//                     items:
//                         type: object
//                         properties:
//                             tcb:
//                                 type: object
//                                 properties:
//                                     isvsvn:
//                                         description: SGX Enclave's ISV SVN
//                                         type: integer
//                             tcbDate:
//                                 type: string
//                                 format: date-time
//                                 description: >-
//                                     If there are security advisories published by Intel after tcbDate
//                                     that are for issues whose mitigations are currently enforced* by SGX attestation,
//                                     then the value of tcbStatus for the TCB level will not be UpToDate.
//                                     Otherwise (i.e., either no advisories after or not currently enforced),
//                                     the value of tcbStatus for the TCB level will not be OutOfDate.
// 
//                                     The time shall be in UTC and the encoding shall
//                                     be compliant to ISO 8601 standard (YYYY-MM-DDThh:mm:ssZ).
//                             tcbStatus:
//                                 type: string
//                                 enum:
//                                     - UpToDate
//                                     - OutOfDate
//                                     - Revoked
//                                 description: >-
//                                     TCB level status. One of the following values:
// 
//                                     "UpToDate" - TCB level of the SGX platform is up-to-date.
// 
//                                     "OutOfDate" - TCB level of SGX platform is outdated.
// 
//                                     "Revoked" - TCB level of SGX platform is revoked.
//                                     The platform is not trustworthy.
//                             advisoryIDs:
//                                 type: array
//                                 description: >-
//                                     Array of Advisory IDs referring to Intel security advisories that
//                                     provide insight into the reason(s) for the value of tcbStatus for
//                                     this TCB level when the value is not UpToDate.
// 
//                                     This field is optional. It will be present only
//                                     if the list of Advisory IDs is not empty.
//                                 items:
//                                     type: string
//         signature:
//             type: string
//             description: Hex-encoded string representation of a signature calculated
//                 over qeIdentity body (without whitespaces) using TCB Info Signing Key.

#[derive(Copy, PartialEq, Drop)]
pub struct EnclaveIdentityV2 {
    pub enclave_identity: EnclaveIdentityV2Inner,
    pub signature: Signature,
}

#[derive(Copy, PartialEq, Drop)]
pub struct EnclaveIdentityV2Inner {
    pub id: felt252,
    pub version: u64,
    pub issue_date: felt252,
    pub next_update: felt252,
    pub tcb_evaluation_data_number: u64,
    pub miscselect: Span<u8>,
    pub miscselect_mask: Span<u8>,
    pub attributes: Span<u8>,
    pub attributes_mask: Span<u8>,
    pub mrsigner: [u8; 32],
    pub isvprodid: u16,
    pub tcb_levels: Span<EnclaveIdentityV2TcbLevelItem>,
}

#[derive(Default, Debug, Clone, PartialEq, Serde)]
pub struct EnclaveIdentityV2TcbLevelItem {
    pub tcb: EnclaveIdentityV2TcbLevel,
    pub tcb_date: felt252,
    pub tcb_status: ByteArray,
    // #[serde(rename(serialize = "advisoryIDs", deserialize = "advisoryIDs"))]
    // #[serde(skip_serializing_if = "Option::is_none")]
    pub advisory_ids: Option<Span<felt252>>,
}

#[derive(Default, Debug, Clone, PartialEq, Serde, Drop)]
pub struct EnclaveIdentityV2TcbLevel {
    pub isvsvn: u16,
}
