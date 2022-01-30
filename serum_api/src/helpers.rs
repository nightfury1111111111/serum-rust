use std::borrow::Cow;
use rand::rngs::OsRng;
use solana_client::{
     rpc_client::RpcClient,
     rpc_config,
     rpc_response::{RpcSimulateTransactionResult,RpcResult},
     rpc_request::RpcRequest
};
use solana_sdk::{commitment_config::CommitmentConfig,
    instruction::Instruction,
    pubkey::Pubkey,
    signature::{Keypair, Signer, Signature},
    transaction::Transaction,
};
use safe_transmute::transmute_many_pedantic;
use anyhow::{Result, format_err};
use byteorder::{LittleEndian, ReadBytesExt};

use bytemuck::bytes_of;

pub fn create_dex_account(
    client: &RpcClient,
    program_id: &Pubkey,
    payer: &Pubkey,
    unpadded_len: usize,
) -> Result<(Keypair, Instruction)> {
    let len = unpadded_len;
    let key = Keypair::generate(&mut OsRng);
    let create_account_instr = solana_sdk::system_instruction::create_account(
        payer,
        &key.pubkey(),
        client.get_minimum_balance_for_rent_exemption(len)?,
        len as u64,
        program_id,
    );
    Ok((key, create_account_instr))
}

pub fn remove_dex_account_padding<'a>(data: &'a [u8]) -> Result<Cow<'a, [u64]>> {
    use serum_dex::state::{ACCOUNT_HEAD_PADDING, ACCOUNT_TAIL_PADDING};
    let head = &data[..ACCOUNT_HEAD_PADDING.len()];
    if data.len() < ACCOUNT_HEAD_PADDING.len() + ACCOUNT_TAIL_PADDING.len() {
        return Err(format_err!(
            "dex account length {} is too small to contain valid padding",
            data.len()
        ));
    }
    if head != ACCOUNT_HEAD_PADDING {
        return Err(format_err!("dex account head padding mismatch"));
    }
    let tail = &data[data.len() - ACCOUNT_TAIL_PADDING.len()..];
    if tail != ACCOUNT_TAIL_PADDING {
        return Err(format_err!("dex account tail padding mismatch"));
    }
    let inner_data_range = ACCOUNT_HEAD_PADDING.len()..(data.len() - ACCOUNT_TAIL_PADDING.len());
    let inner: &'a [u8] = &data[inner_data_range];
    let words: Cow<'a, [u64]> = match transmute_many_pedantic::<u64>(inner) {
        Ok(word_slice) => Cow::Borrowed(word_slice),
        Err(transmute_error) => {
            let word_vec = transmute_error.copy().map_err(|e| e.without_src())?;
            Cow::Owned(word_vec)
        }
    };
    Ok(words)
}

pub fn send_txn(client: &RpcClient, txn: &Transaction, _simulate: bool) -> Result<Signature> {
    Ok(client.send_and_confirm_transaction_with_spinner_and_config(
        txn,
        CommitmentConfig::confirmed(),
        rpc_config::RpcSendTransactionConfig {
            skip_preflight: true,
            ..rpc_config::RpcSendTransactionConfig::default()
        },
    )?)
}

pub fn simulate_transaction(
    client: &RpcClient,
    transaction: &Transaction,
    sig_verify: bool,
    cfg: CommitmentConfig,
) -> RpcResult<RpcSimulateTransactionResult> {
    let serialized_encoded = bs58::encode(bincode::serialize(transaction).unwrap()).into_string();
    client.send(
        RpcRequest::SimulateTransaction,
        serde_json::json!([serialized_encoded, {
            "sigVerify": sig_verify, "commitment": cfg.commitment
        }]),
    )
}

pub fn convert64_to_pubkey(arr: [u64; 4]) -> Pubkey {

    let mut key: [u8; 32] = [0; 32];
    arr.iter()
        .flat_map(|x| x.to_le_bytes())
        .enumerate()
        .for_each(|(i, x)| key[i] = x);

    Pubkey::new_from_array(key)

}

pub fn convert_pubkey_to_64<>(key: &Pubkey) -> [u64; 4] {
    
    let bytes = key.to_bytes();
    let mut arr:[u64; 4] = [0, 0, 0, 0];

    for i in 0..4 {
        let mut buf: &[u8] = &bytes[i*8..i*8+8];
        arr[i] = buf.read_u64::<LittleEndian>().unwrap();
    }

    arr

}

fn gen_vault_signer_seeds<'a>(nonce: &'a u64, market: &'a Pubkey) -> [&'a [u8]; 2] {
    [market.as_ref(), bytes_of(nonce)]
}

pub fn gen_vault_signer_key(
    nonce: u64,
    market: &Pubkey,
    program_id: &Pubkey,
) -> Result<Pubkey> {
    let seeds = gen_vault_signer_seeds(&nonce, market);
    Ok(Pubkey::create_program_address(&seeds, program_id)?)
}

