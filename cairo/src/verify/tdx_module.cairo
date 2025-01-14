use crate::types::tcbinfo::TcbInfoV3;
use crate::types::TcbStatus;
use crate::utils::byte::{felt252s_to_u64, u8s_to_felt252s};
use crate::types::TcbStatusImpl;
use cairo::utils::byte::SpanU8TryIntoArrayU8Fixed48;

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L62-L97
pub fn get_tdx_module_identity_and_tcb(
    tee_tcb_svn: @[u8; 16],
    tcb_info_v3: @TcbInfoV3,
) -> (TcbStatus, [u8; 48], u64) {
    assert!(tcb_info_v3.tcb_info.tdx_module.is_some(), "TDX module not found");
    let tdx_module = (*tcb_info_v3.tcb_info.tdx_module).unwrap();

    let tdx_module_isv_svn = tee_tcb_svn.span()[0];
    let tdx_module_version = tee_tcb_svn.span()[1];

    if *tdx_module_version == 0_u8 {
        let mrsigner: [u8; 48] = tdx_module.mrsigner.try_into().unwrap();
        let attributes_felt: Span<felt252> = u8s_to_felt252s(tdx_module.attributes.span()).span();
        return (
            TcbStatus::OK,
            mrsigner,
            felt252s_to_u64(attributes_felt),
        );
    }

    let tdx_module_identity_id: u8 = *tdx_module_version;
    let mut result = (TcbStatus::TcbUnrecognized, [0; 48], 0);
    if let Option::Some(tdx_module_identities) = tcb_info_v3.tcb_info.tdx_module_identities {
        let mut found = false;
    
        let len = tdx_module_identities.deref().len();
        for i in 0..len {
            let tdx_module_identity = *tdx_module_identities[i];
            
            if tdx_module_identity.id == tdx_module_identity_id {
                let tcb_levels_len = tdx_module_identity.tcb_levels.len();
                for j in 0..tcb_levels_len {
                    let tcb_level = tdx_module_identity.tcb_levels[j];
                    
                    if tdx_module_isv_svn >= tcb_level.tcb.isvsvn {
                        let mrsigner: [u8; 48] = tdx_module_identity.mrsigner.try_into().unwrap();
                        let attributes_felt: Span<felt252> = u8s_to_felt252s(tdx_module.attributes.span()).span();
                        let tcb_status = TcbStatusImpl::from_str(tcb_level.tcb_status.clone());
                        result = (tcb_status, mrsigner, felt252s_to_u64(attributes_felt));
                        found = true;
                        break;
                    }
                };
                if found {
                    break;
                }
            }
        };
    
        if found {
            result
        } else {
            panic!("TDX Module could not match to any TCB Level for TSX Module ISVSN: {}", tdx_module_isv_svn)
        }
    } else {
        panic!("TDX module identities not found")
    }

    result
}

// https://github.com/intel/SGX-TDX-DCAP-QuoteVerificationLibrary/blob/7e5b2a13ca5472de8d97dd7d7024c2ea5af9a6ba/Src/AttestationLibrary/src/Verifiers/Checks/TdxModuleCheck.cpp#L99-L137
pub fn converge_tcb_status_with_tdx_module_tcb(
    tcb_status: TcbStatus,
    tdx_module_tcb_status: TcbStatus,
) -> TcbStatus {
    let converged_tcb_status = match tdx_module_tcb_status {
        TcbStatus::TcbOutOfDate => {
            if tcb_status == TcbStatus::OK || tcb_status == TcbStatus::TcbSwHardeningNeeded {
                TcbStatus::TcbOutOfDate
            } else if tcb_status == TcbStatus::TcbConfigurationNeeded
                || tcb_status == TcbStatus::TcbConfigurationAndSwHardeningNeeded
            {
                TcbStatus::TcbOutOfDateConfigurationNeeded
            } else {
                tcb_status
            }
        },
        _ => {
            tcb_status
        }
    };
    converged_tcb_status
}
