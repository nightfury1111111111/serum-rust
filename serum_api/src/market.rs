use solana_sdk::pubkey::Pubkey;
use serum_dex::state::MarketState;
use anyhow::Result;
use std::fs;
use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use rust_decimal::prelude::*;

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct OpenOrderData {
    pub reserv1: [u8; 5],
    pub account_flags: u64,
    pub market: [u64; 4],
    pub owner: [u64; 4],
    pub base_token_free: u64,
    pub base_token_total: u64,
    pub quote_token_rfee: u64,
    pub quote_token_total: u64,
    pub free_slot_bits: u128,
    pub is_bid_bits: u128,
    pub orders: [u128; 128],
    pub client_ids: [u64; 128],
    pub referrer_rebates_accrued: u64,
    pub reserv2: [u8; 7],
}

#[derive(Debug)]
pub struct Order {
    pub order_id: u128,
    pub price: Decimal,
    pub quantity: Decimal,
    pub slot: u8,
    pub client_order_id: u64,
    pub owner: Pubkey,
    pub side: serum_dex::matching::Side,
}

pub struct MarketParsed{
    pub state: MarketState,
    pub pc_decimal: u8,
    pub coin_decimal: u8,
    pub own_adr: Pubkey,
    pub coin_mint_adr: Pubkey,
    pub pc_mint_adr: Pubkey,
    pub coin_vault_adr: Pubkey,
    pub pc_vault_adr: Pubkey,
    pub req_q_adr: Pubkey,
    pub event_q_adr: Pubkey,
    pub bids_adr: Pubkey,
    pub asks_adr: Pubkey,
    pub vault_signer_nonce: Pubkey,
    pub coin_lot: u64,
    pub pc_lot: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct RawMarketAdr{
    address: String,
    name: String,
    deprecated: bool,
    programId: String,
}

#[derive(Debug, Clone)]
pub struct MarketAdr{
    pub name: String,
    pub deprecated: bool,
    pub program_id: Pubkey,
}

pub fn load_markets_adr_from_file(path: &String) -> Result<HashMap<Pubkey, MarketAdr>> {
    let raw_info = fs::read_to_string(path).expect("Error read file");
    let vec: Vec<RawMarketAdr> = serde_json::from_str(&raw_info)?;
    let res:HashMap<Pubkey, MarketAdr> = vec
    .iter()
    .map(|x| {
        let key = Pubkey::from_str(&x.address).unwrap();
        (key, MarketAdr{
            name: (x.name).to_string(),
            deprecated: x.deprecated,
            program_id: Pubkey::from_str(&x.programId).unwrap(),
        })

    })
    .collect();
    Ok(res)
}
