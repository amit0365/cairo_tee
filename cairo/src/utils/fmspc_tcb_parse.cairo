// fn get_fmspc_tcb_v3(id: TcbId, fmspc: Span<u8>) -> (bool, Array<TcbLevelsObj>, TdxModule, Array<TdxModuleIdentity>) {
//     // todo: implement this
//     let key = FMSPC_TCB_KEY(id, fmspc, 3);
//     let data = _fetch_data_from_resolver(key, false);
//     let valid = data.len() > 0;
    
//     if valid {
//         let (tcb_info, tdx_module, encoded_tdx_module_identities, encoded_levels) = abi::decode(data);
//         let tcb_levels = _decode_tcb_levels(encoded_levels);
//         let tdx_module_identities = if encoded_tdx_module_identities.len() > 0 {
//             _decode_tdx_module_identities(encoded_tdx_module_identities)
//         } else {
//             ArrayTrait::new()
//         };
//         (true, tcb_levels, tdx_module, tdx_module_identities)
//     } else {
//         (false, ArrayTrait::new(), TdxModule::default(), ArrayTrait::new())
//     }
// }

// function getFmspcTcbV2(bytes6 fmspc)
// external
// view
// returns (bool valid, TCBLevelsObj[] memory tcbLevelsV2)
// {
// bytes32 key = FMSPC_TCB_KEY(uint8(TcbId.SGX), fmspc, 2);
// TcbInfoBasic memory tcbInfo;
// bytes memory data = _fetchDataFromResolver(key, false);
// valid = data.length > 0;
// if (valid) {
//     bytes memory encodedLevels;
//     (tcbInfo, encodedLevels,,) = abi.decode(data, (TcbInfoBasic, bytes, string, bytes));
//     tcbLevelsV2 = _decodeTcbLevels(encodedLevels);
// }
// }

use core::array::SpanTrait;
use core::array::ArrayTrait;
use crate::types::tcbinfo::{TcbId, TCBLevelsObj, TDXModule, TDXModuleIdentity};



// function FMSPC_TCB_KEY(uint8 tcbType, bytes6 fmspc, uint32 version) public pure returns (bytes32 key) {
//     key = keccak256(abi.encodePacked(FMSPC_TCB_MAGIC, tcbType, fmspc, version));
// }

// fn get_fmspc_tcb_v3(id: TcbId, fmspc: Span<u8>) -> (bool, Array<TCBLevelsObj>, TDXModule, Array<TDXModuleIdentity>) {
//     // todo: implement this
//     let key = //FMSPC_TCB_KEY(id, fmspc, 3); FIX THIS FOR NOW TODO
//     let data = _fetch_data_from_resolver(key, false);
//     let valid = data.len() > 0;
    
//     if valid {
//         let (tcb_info, tdx_module, encoded_tdx_module_identities, encoded_levels, _, _) = abi::decode(data);
//         let tcb_levels = _decode_tcb_levels(encoded_levels);
//         let tdx_module_identities = if encoded_tdx_module_identities.len() > 0 {
//             _decode_tdx_module_identities(encoded_tdx_module_identities)
//         } else {
//             ArrayTrait::new()
//         };
//         (true, tcb_levels, tdx_module, tdx_module_identities)
//     } else {
//         (false, ArrayTrait::new(), TdxModule::default(), ArrayTrait::new())
//     }
// }

// function getFmspcTcbV3(TcbId id, bytes6 fmspc)
// external
// view
// returns (
//     bool valid,
//     TCBLevelsObj[] memory tcbLevelsV3,
//     TDXModule memory tdxModule,
//     TDXModuleIdentity[] memory tdxModuleIdentities
// )
// {
//     bytes32 key = FMSPC_TCB_KEY(uint8(id), fmspc, 3);
//     TcbInfoBasic memory tcbInfo;
//     bytes memory data = _fetchDataFromResolver(key, false);
//     valid = data.length > 0;
//     if (valid) {
//         bytes memory encodedLevels;
//         bytes memory encodedTdxModuleIdentities;
//         (tcbInfo, tdxModule, encodedTdxModuleIdentities, encodedLevels,,) =
//             abi.decode(data, (TcbInfoBasic, TDXModule, bytes, bytes, string, bytes));
//         tcbLevelsV3 = _decodeTcbLevels(encodedLevels);
//         if (encodedTdxModuleIdentities.length > 0) {
//             tdxModuleIdentities = _decodeTdxModuleIdentities(encodedTdxModuleIdentities);
//         }
//         console.log("tcb levels before optimization length: ", abi.encode(tcbLevelsV3).length);
//         console.log("tcb levels after optimization length: ", encodedLevels.length);
//         console.log("tdxmodule id tcb levels before optimization length: ", abi.encode(tdxModuleIdentities).length);
//         console.log("tdxmodule id tcb levels after optimization length: ", encodedTdxModuleIdentities.length);
//     }
// }

// function _decodeTcbLevels(bytes memory encodedTcbLevels) private view returns (TCBLevelsObj[] memory tcbLevels) {
// bytes[] memory encodedTcbLevelsArr = abi.decode(encodedTcbLevels, (bytes[]));
// uint256 n = encodedTcbLevelsArr.length;
// tcbLevels = new TCBLevelsObj[](n);
// for (uint256 i = 0; i < n;) {
//     tcbLevels[i] = FmspcTcbLib.tcbLevelsObjFromBytes(encodedTcbLevelsArr[i]);
//     unchecked {
//         i++;
//     }
// }
// }

// function _decodeTdxModuleIdentities(bytes memory encodedTdxModuleIdentities) private view returns (TDXModuleIdentity[] memory tdxModuleIdentities) {
// bytes[] memory encodedTdxModuleIdentitiesArr = abi.decode(encodedTdxModuleIdentities, (bytes[]));
// uint256 n = encodedTdxModuleIdentitiesArr.length;
// tdxModuleIdentities = new TDXModuleIdentity[](n);
// for (uint256 i = 0; i < n;) {
//     tdxModuleIdentities[i] = FmspcTcbLib.tdxModuleIdentityFromBytes(encodedTdxModuleIdentitiesArr[i]);
//     unchecked {
//         i++;
//     }
// }
// }