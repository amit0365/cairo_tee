

enum EnclaveId {
    QE,
    QVE,
    TD_QE
}

// /**
//  * @dev This is a simple representation of the Identity.json in string as a Solidity object.
//  * @param identityStr Identity string object body. Needs to be parsed
//  * and converted as IdentityObj.
//  * @param signature The signature to be passed as bytes array
//  */
struct EnclaveIdentityJsonObj {
    identityStr: Span<u8>,
    signature: Span<u8>
}

/// @dev Full Solidity Object representation of Identity.json
struct IdentityObj {
    id: EnclaveId,
    version: u32,
    issueDateTimestamp: u64, // UNIX Epoch Timestamp in seconds
    nextUpdateTimestamp: u64, // UNIX Epoch Timestamp in seconds
    tcbEvaluationDataNumber: u32,
    miscselect: u32,
    miscselectMask: u32,
    attributes: Span<u8>,
    attributesMask: Span<u8>,
    mrsigner: Span<u8>,
    isvprodid: u16,
    tcb: Span<u8>
}

enum EnclaveIdTcbStatus {
    SGX_ENCLAVE_REPORT_ISVSVN_NOT_SUPPORTED,
    OK,
    SGX_ENCLAVE_REPORT_ISVSVN_REVOKED,
    SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE
}

struct Tcb {
    isvsvn: u16,
    dateTimestamp: u64,
    status: EnclaveIdTcbStatus
}

// /**
//  * @title Enclave Identity Helper Contract
//  * @notice This is a standalone contract that can be used by off-chain applications and smart contracts
//  * to parse Identity.json, and convert as a Solidity object.
//  */
#[generate_trait]
impl EnclaveIdentityHelperImpl of EnclaveIdentityHelperTrait {

    // fn parseIdentityString(self: Span<u8>) -> IdentityObj {
    //     let identity = self.parse_identity();
    //     identity
    // }

    // function parseIdentityString(string calldata identityStr) external pure returns (IdentityObj memory identity) {
    //     identity = _parseIdentity(identityStr);
    // }

    
    // function _parseIdentity(string calldata identityStr) private pure returns (IdentityObj memory identity) {
    //     JSONParserLib.Item memory root = JSONParserLib.parse(identityStr);
    //     JSONParserLib.Item[] memory identityObj = root.children();

    //     for (uint256 i = 0; i < root.size(); i++) {
    //         JSONParserLib.Item memory current = identityObj[i];
    //         string memory decodedKey = JSONParserLib.decodeString(current.key());

    //         if (decodedKey.eq("issueDate")) {
    //             identity.issueDateTimestamp =
    //                 uint64(DateTimeUtils.fromISOToTimestamp(JSONParserLib.decodeString(current.value())));
    //         } else if (decodedKey.eq("nextUpdate")) {
    //             identity.nextUpdateTimestamp =
    //                 uint64(DateTimeUtils.fromISOToTimestamp(JSONParserLib.decodeString(current.value())));
    //         } else if (decodedKey.eq("id")) {
    //             string memory idStr = JSONParserLib.decodeString(current.value());
    //             if (LibString.eq(idStr, "QE")) {
    //                 identity.id = EnclaveId.QE;
    //             } else if (LibString.eq(idStr, "QVE")) {
    //                 identity.id = EnclaveId.QVE;
    //             } else if (LibString.eq(idStr, "TD_QE")) {
    //                 identity.id = EnclaveId.TD_QE;
    //             } else {
    //                 revert Invalid_ID();
    //             }
    //         } else if (decodedKey.eq("version")) {
    //             identity.version = uint32(JSONParserLib.parseUint(current.value()));
    //         } else if (decodedKey.eq("tcbEvaluationDataNumber")) {
    //             identity.tcbEvaluationDataNumber = uint32(JSONParserLib.parseUint(current.value()));
    //         } else if (decodedKey.eq("miscselect")) {
    //             uint256 val = JSONParserLib.parseUintFromHex(JSONParserLib.decodeString(current.value()));
    //             identity.miscselect = bytes4(uint32(val));
    //         } else if (decodedKey.eq("miscselectMask")) {
    //             uint256 val = JSONParserLib.parseUintFromHex(JSONParserLib.decodeString(current.value()));
    //             identity.miscselectMask = bytes4(uint32(val));
    //         } else if (decodedKey.eq("attributes")) {
    //             uint256 val = JSONParserLib.parseUintFromHex(JSONParserLib.decodeString(current.value()));
    //             identity.attributes = bytes16(uint128(val));
    //         } else if (decodedKey.eq("attributesMask")) {
    //             uint256 val = JSONParserLib.parseUintFromHex(JSONParserLib.decodeString(current.value()));
    //             identity.attributesMask = bytes16(uint128(val));
    //         } else if (decodedKey.eq("mrsigner")) {
    //             uint256 val = JSONParserLib.parseUintFromHex(JSONParserLib.decodeString(current.value()));
    //             identity.mrsigner = bytes32(val);
    //         } else if (decodedKey.eq("isvprodid")) {
    //             identity.isvprodid = uint16(JSONParserLib.parseUint(current.value()));
    //         } else if (decodedKey.eq("tcbLevels")) {
    //             identity.tcb = _parseTcb(current.value());
    //         }
    //     }
    // }

    // fn parse_tcb(tcb_levels_str: ByteArray) -> Array<Tcb> {
    //     let tcb_levels_parent = JsonTrait::parse(tcb_levels_str);
    //     let tcb_levels = tcb_levels_parent.children();
    //     let tcb_levels_size = tcb_levels_parent.size();
        
    //     let mut tcb = ArrayTrait::new();
    
    //     // Iterate through TCB levels
    //     for i in 0..tcb_levels_size {
    //         let mut current_tcb = Tcb { 
    //             isvsvn: 0, 
    //             date_timestamp: 0, 
    //             status: EnclaveIdTcbStatus::Unknown 
    //         };
            
    //         let tcb_obj = tcb_levels.at(i).children();
    //         let tcb_levels_child_size = tcb_levels.at(i).size();
    
    //         // Parse each TCB object
    //         for j in 0..tcb_levels_child_size {
    //             let tcb_key = tcb_obj.at(j).key().decode_string();
                
    //             match tcb_key {
    
    //                 "tcb" => {
    //                     let tcb_child = tcb_obj.at(j).children();
    //                     let child_key = tcb_child.at(0).key().decode_string();
    //                     if child_key == "isvsvn" {
    //                         current_tcb.isvsvn = tcb_child.at(0).value().parse_uint().try_into().unwrap();
    //                     }
    //                 },
    //                 "tcbDate" => {
    //                     current_tcb.date_timestamp = DateTimeUtils::from_iso_to_timestamp(
    //                         tcb_obj.at(j).value().decode_string()
    //                     );
    //                 },
    //                 "tcbStatus" => {
    //                     let status_str = tcb_obj.at(j).value().decode_string();
    //                     current_tcb.status = match status_str {
    //                         "UpToDate" => EnclaveIdTcbStatus::OK,
    //                         "Revoked" => EnclaveIdTcbStatus::SgxEnclaveReportIsvsvnRevoked,
    //                         "OutOfDate" => EnclaveIdTcbStatus::SgxEnclaveReportIsvsvnOutOfDate,
    //                         _ => EnclaveIdTcbStatus::Unknown,
    //                     };
    //                 },
    //                 _ => {},
    //             };
    //         }

    //         tcb.append(current_tcb);
    //     };

    //     tcb
    // }

    // function _parseTcb(string memory tcbLevelsStr) internal pure returns (Tcb[] memory tcb) {
    //     JSONParserLib.Item memory tcbLevelsParent = JSONParserLib.parse(tcbLevelsStr);
    //     JSONParserLib.Item[] memory tcbLevels = tcbLevelsParent.children();
    //     uint256 tcbLevelsSize = tcbLevelsParent.size();
    //     tcb = new Tcb[](tcbLevelsSize);
    //     for (uint256 i = 0; i < tcbLevelsSize; i++) {
    //         uint256 tcbLevelsChildSize = tcbLevels[i].size();
    //         JSONParserLib.Item[] memory tcbObj = tcbLevels[i].children();
    //         for (uint256 j = 0; j < tcbLevelsChildSize; j++) {
    //             string memory tcbKey = JSONParserLib.decodeString(tcbObj[j].key());
    //             if (tcbKey.eq("tcb")) {
    //                 JSONParserLib.Item[] memory tcbChild = tcbObj[j].children();
    //                 string memory childKey = JSONParserLib.decodeString(tcbChild[0].key());
    //                 if (childKey.eq("isvsvn")) {
    //                     tcb[i].isvsvn = uint16(JSONParserLib.parseUint(tcbChild[0].value()));
    //                 }
    //             } else if (tcbKey.eq("tcbDate")) {
    //                 tcb[i].dateTimestamp =
    //                     DateTimeUtils.fromISOToTimestamp(JSONParserLib.decodeString(tcbObj[j].value()));
    //             } else if (tcbKey.eq("tcbStatus")) {
    //                 string memory decodedValue = JSONParserLib.decodeString(tcbObj[j].value());
    //                 if (decodedValue.eq("UpToDate")) {
    //                     tcb[i].status = EnclaveIdTcbStatus.OK;
    //                 } else if (decodedValue.eq("Revoked")) {
    //                     tcb[i].status = EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_REVOKED;
    //                 } else if (decodedValue.eq("OutOfDate")) {
    //                     tcb[i].status = EnclaveIdTcbStatus.SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE;
    //                 }
    //             }
    //         }
    //     }
    // }
}
