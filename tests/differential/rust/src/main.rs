use alloy_primitives::Address;
use std::{
    io::{self, BufRead},
    sync::Arc,
};
use tempo_primitives::transaction::AASigned;

// Compare canonical encoding and both signing domains, including each delegation.
fn process(input: &[u8]) -> Result<Vec<u8>, String> {
    if input.first() != Some(&0x76) {
        return Err("expected signed Tempo transaction".into());
    }
    let mut buf = &input[1..];
    let signed = AASigned::rlp_decode(&mut buf).map_err(|e| e.to_string())?;
    if !buf.is_empty() {
        return Err("trailing bytes".into());
    }
    let mut result = Vec::new();
    signed.eip2718_encode(&mut result);
    result.extend_from_slice(signed.signature_hash().as_slice());
    result.extend_from_slice(
        signed
            .tx()
            .fee_payer_signature_hash(Address::repeat_byte(0x11))
            .as_slice(),
    );
    for auth in &signed.tx().tempo_authorization_list {
        result.extend_from_slice(auth.signature_hash().as_slice());
    }
    Ok(result)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::args().any(|s| s == "--abis") {
        use tempo_contracts::precompiles::*;
        let mut contracts = serde_json::Map::new();
        macro_rules! export {
            ($name:ident, $address:expr) => {{
                let abi = $name::abi::contract();
                let selectors: std::collections::BTreeMap<_, _> = abi.functions().map(|f| (f.signature(), hex::encode(f.selector()))).collect();
                contracts.insert(stringify!($name).into(), serde_json::json!({"abi": abi, "address": $address, "selectors": selectors}));
            }};
        }
        export!(IAccountKeychain, Some(ACCOUNT_KEYCHAIN_ADDRESS));
        export!(IAddressRegistry, Some(ADDRESS_REGISTRY_ADDRESS));
        export!(ICurrentCommittee, Some(CURRENT_COMMITTEE_ADDRESS));
        export!(INonce, Some(NONCE_PRECOMPILE_ADDRESS));
        export!(IReceivePolicyGuard, Some(RECEIVE_POLICY_GUARD_ADDRESS));
        export!(ISignatureVerifier, Some(SIGNATURE_VERIFIER_ADDRESS));
        export!(IStablecoinDEX, Some(STABLECOIN_DEX_ADDRESS));
        export!(IStorageCredits, Some(STORAGE_CREDITS_ADDRESS));
        export!(ITIP20, None::<Address>);
        export!(IRolesAuth, None::<Address>);
        export!(ITIP20ChannelReserve, None::<Address>);
        export!(ITIP20Factory, Some(TIP20_FACTORY_ADDRESS));
        export!(ITIP403Registry, Some(TIP403_REGISTRY_ADDRESS));
        export!(IFeeManager, Some(TIP_FEE_MANAGER_ADDRESS));
        export!(ITIPFeeAMM, Some(TIP_FEE_MANAGER_ADDRESS));
        export!(IValidatorConfig, Some(VALIDATOR_CONFIG_ADDRESS));
        export!(IValidatorConfigV2, Some(VALIDATOR_CONFIG_V2_ADDRESS));
        export!(IZoneFactory, None::<Address>);
        export!(IZonePortal, None::<Address>);
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"revision":"07761a78a4ac00988533aa8acbcb6667786b625d", "contracts": contracts})
            )?
        );
        return Ok(());
    }
    if std::env::args().any(|s| s == "--stdin") {
        for line in io::stdin().lock().lines() {
            let input = hex::decode(line?)?;
            println!("{}", hex::encode(process(&input)?));
        }
        return Ok(());
    }
    tokio::runtime::Runtime::new()?.block_on(async {
        let callback = Arc::new(|method: &str, inputs: &[&[u8]]| -> dff::Result<Vec<u8>> {
            if method != "tempo-codec" || inputs.len() != 1 {
                return Err(dff::Error::Client("invalid request".into()));
            }
            process(inputs[0]).map_err(dff::Error::Client)
        });
        let mut client = dff::Client::new("rust".into(), callback);
        client.connect().await?;
        std::fs::write("rust.ready", b"ready")?;
        client.run().await?;
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
