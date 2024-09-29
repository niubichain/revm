use std::io::Cursor;

use arith::FieldSerde;
use ethabi::{ParamType, Token};
use expander::{BN254ConfigSha2, Circuit, Config, GKRScheme, MPIConfig, Proof, Verifier};
use halo2curves::bn256::Fr;
use revm_primitives::Bytes;

use crate::{
    Precompile, PrecompileError, PrecompileErrors, PrecompileOutput, PrecompileResult,
    PrecompileWithAddress,
};

pub const VERIFY_EXPANDER: PrecompileWithAddress = PrecompileWithAddress(
    crate::u64_to_address(0xff03),
    Precompile::Standard(verify_expander),
);

const GAS: u64 = 7500;

fn verify_expander(input: &Bytes, _gas_limit: u64) -> PrecompileResult {
    let tokens = ethabi::decode(
        &[ParamType::Bytes, ParamType::Bytes, ParamType::Bytes],
        &input,
    )
    .map_err(|e| {
        PrecompileErrors::Error(PrecompileError::other(format!("decode input error:{e}")))
    })?;

    let circuit_bytes = tokens
        .first()
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify expander circuit format error",
        )))?;

    let witness_bytes = tokens
        .get(1)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify expander witness format error",
        )))?;

    let proof_bytes = tokens
        .get(2)
        .cloned()
        .and_then(|token| token.into_bytes())
        .ok_or(PrecompileErrors::Error(PrecompileError::other(
            "verify expander proof format error",
        )))?;

    let mut circuit =
        Circuit::<BN254ConfigSha2>::load_circuit_bytes(circuit_bytes).map_err(|e| {
            PrecompileErrors::Error(PrecompileError::other(format!(
                "load_circuit_bytes error:{e}"
            )))
        })?;

    circuit.load_witness_bytes(&witness_bytes).map_err(|e| {
        PrecompileErrors::Error(PrecompileError::other(format!(
            "load_witness_bytes error:{e}"
        )))
    })?;

    let config = Config::<BN254ConfigSha2>::new(GKRScheme::Vanilla, MPIConfig::new());
    let verifier = Verifier::new(&config);

    let mut cursor = Cursor::new(proof_bytes);
    let proof = Proof::deserialize_from(&mut cursor).map_err(|e| {
        PrecompileErrors::Error(PrecompileError::other(format!("format proof error:{e}")))
    })?;
    let claimed_v = Fr::deserialize_from(&mut cursor).map_err(|e| {
        PrecompileErrors::Error(PrecompileError::other(format!("format claimed error:{e}")))
    })?;

    let ret = verifier.verify(&mut circuit, &claimed_v, &proof);
    let bytes = ethabi::encode(&[Token::Bool(ret)]);

    Ok(PrecompileOutput::new(GAS, bytes.into()))
}
