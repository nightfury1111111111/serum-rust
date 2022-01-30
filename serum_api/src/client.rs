use std::{
    assert_eq, 
    borrow::Cow, 
    collections::HashMap, 
    convert::identity, 
    error::Error, 
    mem::size_of, 
    num::NonZeroU64, 
    ops::DerefMut, sync::Arc};
use rust_decimal::prelude::*;
use anyhow::{Result, format_err};
use serum_dex::{
    instruction::cancel_order as cancel_order_ix,
    critbit::SlabView,
    state::{
        AccountFlag, 
        Market, 
        MarketState, 
        MarketStateV2
    },
};
use solana_client_helpers::spl_associated_token_account::get_associated_token_address;
use solana_program::{program_pack::Pack, pubkey::Pubkey};
use solana_sdk::{commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    transaction::Transaction,
    account_info::IntoAccountInfo,
    signature::Keypair, 
    signer::Signer
 };
use spl_token::state;
use solana_client::{
    client_error::Result as ClientResult,
    rpc_client::RpcClient,
    rpc_config,
    rpc_filter,
};
use solana_account_decoder;
use safe_transmute::{
    to_bytes::transmute_to_bytes, 
    transmute_one_pedantic, 
};
use crate::market::{self, MarketParsed};
use super::helpers;
use parking_lot::Mutex;
pub struct NetworkOpts{
    url: String,
}

pub enum NetworkType{
    Mainnet,
    Devnet,
    Custom(NetworkOpts)
}

impl NetworkType {
    pub fn url(&self) -> &str {
        match self {
            NetworkType::Devnet => "https://api.devnet.solana.com",
            NetworkType::Mainnet => "https://api.mainnet-beta.solana.com",
            NetworkType::Custom(nework_opts) => &nework_opts.url,
        }
    }
}

pub fn get_rpc_client(network: &NetworkType) -> ClientResult<RpcClient> {
    let client = RpcClient::new(network.url().to_string());

    let version = client.get_version()?;
    println!("RPC version: {:?}", version);
    Ok(client)
}

pub struct Client{
    rpc_client: RpcClient,
    payer: Keypair, 
    markets:  Mutex<HashMap<Pubkey, market::MarketParsed>>,
    markets_adr: HashMap<Pubkey, market::MarketAdr>,
}

impl Client {
    pub fn new (network_type: NetworkType, payer: Keypair, path: &String) -> Result<Self, Box::<dyn Error>> {
        let client = get_rpc_client(&network_type)?;
        let markets_adr = market::load_markets_adr_from_file(path)?;
        Ok(Client {rpc_client: client, payer, markets: Mutex::new(HashMap::new()), markets_adr})
    }
    
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc_client
    }
    pub fn payer(&self) -> Pubkey {
        self.payer.pubkey()
    }

   pub async fn assign_all_markets(self: &Arc<Self>) -> Result<()> {    

        for (market_id, market_adr) in self.markets_adr.iter(){
            if !self.markets.lock().contains_key(market_id) && !market_adr.deprecated{
                self.load_market_data(market_id, &market_adr.program_id).await?;
            };
        };
        println!("assign {} markets", self.markets.lock().len());
        Ok(())
    }

    /// Add data about market in field "markets"
    pub async fn assign_market(self: &Arc<Self> , currency_pair: &String) -> Result<()> {
        let (market_id, market_adr) = match find_pukey_by_currency_pair(&self.markets_adr, currency_pair) {
            Some(tuple) => tuple,
            None => return Err(format_err!("Market for this carrency pair not found")),
        };
        if self.markets.lock().contains_key(market_id){
            Ok(())
        } else {
            self.load_market_data(market_id, &market_adr.program_id).await?;
            Ok(())
        }
    }

    /// Print all pubkeys of market
    pub async fn print_keys(self: &Arc<Self> , currency_pair: &String) -> Result<()> {

        let (market_id, _) = match find_pukey_by_currency_pair(&self.markets_adr, currency_pair) {
            Some(tuple) => tuple,
            None => return Err(format_err!("Market for this carrency pair not found")),
        };

        if self.markets.lock().contains_key(market_id){
            let market = &self.markets.lock()[market_id];
            println!("*********************************");
            println!("own_address:  \t{:?}", &market.own_adr);
            println!("coin_mint:  \t{:?}", &market.coin_mint_adr);
            println!("pc_mint:  \t{:?}", &market.pc_mint_adr);
            println!("coin_vault:  \t{:?}", &market.coin_vault_adr);
            println!("pc_vault:  \t{:?}", &market.pc_vault_adr);
            println!("req_q:  \t{:?}", &market.req_q_adr);
            println!("event_q:  \t{:?}", &market.event_q_adr);
            println!("bids:  \t\t{:?}", &market.bids_adr);
            println!("asks:  \t\t{:?}", &market.asks_adr);
            println!("coin_lot_size:  {:?}", &market.coin_lot);
            println!("pc_lot_size:  \t{:?}", &market.pc_lot);
            println!("pc_decimal:  \t{:?}", &market.pc_decimal);
            println!("coin_decimal:  \t{:?}", &market.coin_decimal);
            println!("*********************************");
        } else {

        self.assign_market(currency_pair).await?;
        let market = &self.markets.lock()[market_id];
        println!("*********************************");
        println!("own_address:  \t{:?}", &market.own_adr);
        println!("coin_mint:  \t{:?}", &market.coin_mint_adr);
        println!("pc_mint:  \t{:?}", &market.pc_mint_adr);
        println!("coin_vault:  \t{:?}", &market.coin_vault_adr);
        println!("pc_vault:  \t{:?}", &market.pc_vault_adr);
        println!("req_q:  \t{:?}", &market.req_q_adr);
        println!("event_q:  \t{:?}", &market.event_q_adr);
        println!("bids:  \t\t{:?}", &market.bids_adr);
        println!("asks:  \t\t{:?}", &market.asks_adr);
        println!("coin_lot_size:  {:?}", &market.coin_lot);
        println!("pc_lot_size:  \t{:?}", &market.pc_lot);
        println!("pc_decimal:  \t{:?}", &market.pc_decimal);
        println!("coin_decimal:  \t{:?}", &market.coin_decimal);
        println!("*********************************");
        }
        Ok(())
    }

    /// Publish new order on market
    pub async fn create_order (
        self: &Arc<Self>,
        currency_pair: &String,
        side: serum_dex::matching::Side,
        price: Decimal,
        size: Decimal,
        order_type: serum_dex::matching::OrderType
    ) -> Result<()>{

        let (market_id, market_adr) = match find_pukey_by_currency_pair(&self.markets_adr, currency_pair) {
            Some(tuple) => tuple,
            None => return Err(format_err!("Market for this carrency pair not found")),
        };

        if !self.markets.lock().contains_key(market_id){
            self.assign_market(currency_pair).await?;
        };

        let mut instructions = Vec::new();
        let mut signers = Vec::new();
        let orders_keypair;

        let open_order_accaunt: Pubkey;
        let vec_pub_ac = self.load_orders_for_owner(*market_id)?;

        if vec_pub_ac.len() > 0 {
            let (a, _) = vec_pub_ac[0];
            open_order_accaunt = a;
        } else {
            let (orders_key, instruction) = helpers::create_dex_account(
                &self.rpc_client,
                &market_adr.program_id,
                &self.payer(),
                size_of::<market::OpenOrderData>(),
            )?;
            orders_keypair = orders_key;
            signers.push(&orders_keypair);
            instructions.push(instruction);
            open_order_accaunt = orders_keypair.pubkey()
        };

        let new_order = serum_dex::instruction::NewOrderInstructionV3{
            side,
            limit_price: NonZeroU64::new(self.make_price(&market_id, price)?).unwrap(),
            max_coin_qty:NonZeroU64::new(self.make_size(&market_id, size)?).unwrap(),
            max_native_pc_qty_including_fees: NonZeroU64::new(self.make_max_native(
                &market_id,self.make_price(&market_id,price)?, 
                 self.make_size(&market_id,size)?)).unwrap(),
            self_trade_behavior: serum_dex::instruction::SelfTradeBehavior::DecrementTake,
            order_type,
            client_order_id: 0x0,   
            limit: std::u16::MAX
        };
        let market = &self.markets.lock()[market_id];
        
        let wallet = match side {
            serum_dex::matching::Side::Bid => get_associated_token_address(&self.payer(), &market.pc_mint_adr),
            serum_dex::matching::Side::Ask => get_associated_token_address(&self.payer(), &market.coin_mint_adr),
        };
        let data = serum_dex::instruction::MarketInstruction::NewOrderV3(new_order).pack();
        let instruction = Instruction {
            program_id: market_adr.program_id,
            data,
            accounts: vec![
                AccountMeta::new(market.own_adr, false),
                AccountMeta::new(open_order_accaunt, false),
                AccountMeta::new(market.req_q_adr, false),
                AccountMeta::new(market.event_q_adr, false),
                AccountMeta::new(market.bids_adr, false),
                AccountMeta::new(market.asks_adr, false),
                AccountMeta::new(wallet, false),
                AccountMeta::new_readonly(self.payer(), true),
                AccountMeta::new(market.coin_vault_adr, false),
                AccountMeta::new(market.pc_vault_adr, false),
                AccountMeta::new_readonly(spl_token::ID, false),
                AccountMeta::new_readonly(solana_sdk::sysvar::rent::ID, false),
            ],
        };
        instructions.push(instruction);
        signers.push(&self.payer);
        signers.push(&self.payer);
        let (recent_hash, _fee_calc) = self.rpc_client.get_recent_blockhash()?;
        let txn = Transaction::new_signed_with_payer(
            &instructions,
            Some(&self.payer()),
            &signers,
            recent_hash,
        );
        helpers::send_txn(&self.rpc_client, &txn, false)?;
        Ok(())
    }

    pub async fn settle_funds(
        self: &Arc<Self>,
        currency_pair: &String,
    )  -> Result<()>{

        let (market_id, market_adr) = match find_pukey_by_currency_pair(&self.markets_adr, currency_pair) {
            Some(tuple) => tuple,
            None => return Err(format_err!("Market for this carrency pair not found")),
        };

        if !self.markets.lock().contains_key(market_id){
            self.assign_market(currency_pair).await?;
        };

        let vec_pub_ac = self.load_orders_for_owner(*market_id)?;
        if vec_pub_ac.len() < 1 {
            return Err(format_err!("Open order accaunts for this carrency pair not found"))
        };

        for (open_order_accaunt, _) in vec_pub_ac {
            let market = &self.markets.lock()[market_id];

            let data = serum_dex::instruction::MarketInstruction::SettleFunds.pack();
            let instruction = Instruction {
                program_id: market_adr.program_id,
                data,
                accounts: vec![
                    AccountMeta::new(*market_id, false),
                    AccountMeta::new(open_order_accaunt, false),
                    AccountMeta::new_readonly(self.payer(), true),
                    AccountMeta::new(market.coin_vault_adr, false),
                    AccountMeta::new(market.pc_vault_adr, false),
                    AccountMeta::new(get_associated_token_address(&self.payer(), &market.coin_mint_adr), false),
                    AccountMeta::new(get_associated_token_address(&self.payer(), &market.pc_mint_adr), false),
                    AccountMeta::new_readonly(market.vault_signer_nonce, false),
                    AccountMeta::new_readonly(spl_token::ID, false),
                ],
            };

            let (recent_hash, _fee_calc) = self.rpc_client.get_recent_blockhash()?;
            let mut signers = vec![&self.payer];
            signers.push(&self.payer);

            let txn = Transaction::new_signed_with_payer(
                &[instruction],
                Some(&self.payer()),
                &signers,
                recent_hash,
            );

            let mut i = 0;
            loop {
                i += 1;
                assert!(i < 10);
                println!("Simulating SettleFunds instruction ...");
                let result = helpers::simulate_transaction(&self.rpc_client, &txn, true, CommitmentConfig::single())?;
                if let Some(e) = result.value.err {
                    return Err(format_err!("simulate_transaction error: {:?}", e));
                }
                // println!("{:#?}", result.value);
                if result.value.err.is_none() {
                    break;
                }
            }
            println!("Settling ...");
            helpers::send_txn(&self.rpc_client, &txn, false)?;
            }
        Ok(())
    } 

    /// Return all orders of all markets 
    pub async fn request_open_orders(
        self: &Arc<Self>,
    ) -> Result<Vec<market::Order>> {

        let mut all_orders: Vec<market::Order> = Vec::new();

        for (market_id, market) in self.markets.lock().iter() {

            let program_id = &self.markets_adr[market_id].program_id;
            let mut result = self.rpc_client.get_account(&market.own_adr)?;
            let acc_info = (program_id, &mut result).into_account_info();

            let market_data = MarketState::load(&acc_info, program_id)?;
        
            let mut asks_account = self.rpc_client.get_account(&market.asks_adr)?;
            let mut bids_account = self.rpc_client.get_account(&market.bids_adr)?;
            let asks_info = (&market.asks_adr, &mut asks_account).into_account_info();
            let bids_info = (&market.bids_adr, &mut bids_account).into_account_info();
            let mut bids = market_data.load_bids_mut(&bids_info)?;
            let mut asks = market_data.load_asks_mut(&asks_info)?;

            let bids_slab = bids.deref_mut();
            let asks_slab = asks.deref_mut();

            for i in 0..bids_slab.capacity() {
                let any_node = bids_slab.get(i as u32);
                match any_node {
                    Some(node) => {
                        match node.as_leaf(){
                            Some(leaf) => {
                                let _ = &all_orders.push(market::Order{
                                    order_id: leaf.order_id(),
                                    price: self.decod_price(market, leaf.price().get())?,
                                    quantity: self.decode_size(market, leaf.quantity())?,
                                    slot: leaf.owner_slot(),
                                    client_order_id: leaf.client_order_id(),
                                    owner: helpers::convert64_to_pubkey(leaf.owner()),
                                    side: serum_dex::matching::Side::Bid,
                                });
                            },
                            None => (),
                        }
                }
                    None => (),
                }
            };

            for i in 0..asks_slab.capacity() {
                let any_node = asks_slab.get(i as u32);
                match any_node {
                    Some(node) => {
                        match node.as_leaf(){
                            Some(leaf) => {
                                let _ = &all_orders.push(market::Order{
                                    order_id: leaf.order_id(),
                                    price: Decimal::from_u64(leaf.price().get()).unwrap(),
                                    quantity: Decimal::from_u64(leaf.quantity()).unwrap(),
                                    slot: leaf.owner_slot(),
                                    client_order_id: leaf.client_order_id(),
                                    owner: helpers::convert64_to_pubkey(leaf.owner()),
                                    side: serum_dex::matching::Side::Ask,
                                });
                            },
                            None => (),
                        }
                }
                    None => (),
                }
            };
        }
        Ok(all_orders)
    }

    /// Return all orders of market
    pub async fn request_open_orders_by_currency_pair(
        self: &Arc<Self>,
        currency_pair: &String,
    ) -> Result<Vec<market::Order>> {

        let (market_id, _) = match find_pukey_by_currency_pair(&self.markets_adr, currency_pair) {
            Some(tuple) => tuple,
            None => return Err(format_err!("Market for this carrency pair not found")),
        };

        if !self.markets.lock().contains_key(market_id){
            self.assign_market(currency_pair).await?;
        };
        
        let market_self = &self.markets.lock()[market_id];
        let program_id = &self.markets_adr[market_id].program_id;

        let mut result = self.rpc_client.get_account(&market_self.own_adr)?;
        let acc_info = (program_id, &mut result).into_account_info();

        let market = MarketState::load(&acc_info, program_id)?;
        
        let mut asks_account = self.rpc_client.get_account(&market_self.asks_adr)?;
        let mut bids_account = self.rpc_client.get_account(&market_self.bids_adr)?;
        let asks_info = (&market_self.asks_adr, &mut asks_account).into_account_info();
        let bids_info = (&market_self.bids_adr, &mut bids_account).into_account_info();
        let mut bids = market.load_bids_mut(&bids_info)?;
        let mut asks = market.load_asks_mut(&asks_info)?;

        let bids_slab = bids.deref_mut();
        let asks_slab = asks.deref_mut();

        let mut all_orders: Vec<market::Order> = Vec::new();
        
        for i in 0..bids_slab.capacity() {
            let any_node = bids_slab.get(i as u32);
            match any_node {
                Some(node) => {
                    match node.as_leaf(){
                        Some(leaf) => {
                            let _ = &all_orders.push(market::Order{
                                order_id: leaf.order_id(),
                                price: self.decod_price(market_self, leaf.price().get())?,
                                quantity: self.decode_size(market_self, leaf.quantity())?,
                                slot: leaf.owner_slot(),
                                client_order_id: leaf.client_order_id(),
                                owner: helpers::convert64_to_pubkey(leaf.owner()),
                                side: serum_dex::matching::Side::Bid,
                            });
                        },
                        None => (),
                    }
            }
                None => (),
            }
        };

        for i in 0..asks_slab.capacity() {
            let any_node = asks_slab.get(i as u32);
            match any_node {
                Some(node) => {
                    match node.as_leaf(){
                        Some(leaf) => {
                            let _ = &all_orders.push(market::Order{
                                order_id: leaf.order_id(),
                                price: Decimal::from_u64(leaf.price().get()).unwrap(),
                                quantity: Decimal::from_u64(leaf.quantity()).unwrap(),
                                slot: leaf.owner_slot(),
                                client_order_id: leaf.client_order_id(),
                                owner: helpers::convert64_to_pubkey(leaf.owner()),
                                side: serum_dex::matching::Side::Ask,
                            });
                        },
                        None => (),
                    }
            }
                None => (),
            }
        };

        Ok(all_orders)
    }

    /// Return payer's orders of market
    pub async fn request_payer_open_orders_by_currency_pair(
        self: &Arc<Self>,
        currency_pair: &String,
    ) -> Result<Vec<market::Order>>{

        let (market_id, _) = match find_pukey_by_currency_pair(&self.markets_adr, currency_pair) {
            Some(tuple) => tuple,
            None => return Err(format_err!("Market for this carrency pair not found")),
        };

        if !self.markets.lock().contains_key(market_id){
            self.assign_market(currency_pair).await?;
        };

        let vec_acc = self.load_orders_for_owner(*market_id)?;

        let mut ids: Vec<u128> = vec!();

        for acc in vec_acc {
            let (_, ac) = acc;
            let account_data = &ac.data;
            let (head, body, _tail) = unsafe { account_data.align_to::<market::OpenOrderData>() };
            assert!(head.is_empty(), "Data was not aligned");
            let open_order_data = &body[0];

            let tmp = open_order_data.orders;
            let mut x = tmp.to_vec();
            ids.append(& mut x);

        };

        let orders = self.request_open_orders_by_currency_pair(currency_pair).await?;

        let mut ret_vol = vec!();

        for order in orders{
            match ids.iter().find(|x| **x == order.order_id) {
                Some(_) => ret_vol.push(order),
                None => (),
            }
        }

        Ok(ret_vol)
    }

    /// Return all payer's orders
    pub async fn request_payer_open_orders(
        self: &Arc<Self>,
    ) -> Result<Vec<market::Order>>{

        let mut all_orders: Vec<market::Order> = Vec::new();

        for market in self.markets.lock().keys() {
            let mut part = self.request_payer_open_orders_by_currency_pair(&self.markets_adr[market].name).await?;
            all_orders.append(& mut part);
        }

        Ok(all_orders)
    }

    /// Canceling order
    pub async fn request_cancel_order(
        self: &Arc<Self>,
        currency_pair: &String,
        order: &market::Order,
    ) -> Result<()> {

        let (market_id, _) = match find_pukey_by_currency_pair(&self.markets_adr, currency_pair) {
            Some(tuple) => tuple,
            None => return Err(format_err!("Market for this carrency pair not found")),
        };

        if !self.markets.lock().contains_key(market_id){
            self.assign_market(currency_pair).await?;
        };

        let market = &self.markets.lock()[market_id];

        let ixs = &[cancel_order_ix(
            &self.markets_adr[market_id].program_id,
            &market.own_adr,
            &market.bids_adr,
            &market.asks_adr,
            &order.owner,
            &self.payer(),
            &market.event_q_adr,
            order.side,
            order.order_id
        )?];
        let (recent_hash, _fee_calc) = self.rpc_client.get_recent_blockhash()?;
        let txn = Transaction::new_signed_with_payer(ixs, Some(&self.payer()), &[&self.payer], recent_hash);
    
        let result = helpers::simulate_transaction(&self.rpc_client, &txn, true, CommitmentConfig::confirmed())?;
        if let Some(e) = result.value.err {
            println!("{:#?}", result.value.logs);
            return Err(format_err!("simulate_transaction error: {:?}", e));
        }
    
        helpers::send_txn(&self.rpc_client, &txn, false)?;
        Ok(())
    }

    /// Canceling all payer's orders on market
    pub async fn cancel_all_orders(
        self: &Arc<Self>,
        currency_pair: &String,
    ) -> Result<()>{

        let (market_id, _) = match find_pukey_by_currency_pair(&self.markets_adr, currency_pair) {
            Some(tuple) => tuple,
            None => return Err(format_err!("Market for this carrency pair not found")),
        };

        if !self.markets.lock().contains_key(market_id){
            self.assign_market(currency_pair).await?;
        };

        let orders = self.request_payer_open_orders_by_currency_pair(currency_pair).await?;
        for order in orders{
            self.request_cancel_order(currency_pair, &order).await?;
        };

        Ok(())
    }
    
    /// return info about order
    pub async fn request_order_info(
        self: &Arc<Self>,
        currency_pair: &String,
        order_id: u128,
    ) -> Result<Option<market::Order>> {

        let (market_id, _) = match find_pukey_by_currency_pair(&self.markets_adr, currency_pair) {
            Some(tuple) => tuple,
            None => return Err(format_err!("Market for this carrency pair not found")),
        };

        if !self.markets.lock().contains_key(market_id){
            self.assign_market(currency_pair).await?;
        };

        let vec_acc = self.load_orders_for_owner(*market_id)?;

        let mut ids: Vec<u128> = vec!();

        for acc in vec_acc {
            let (_, ac) = acc;
            let account_data = &ac.data;
            let (head, body, _tail) = unsafe { account_data.align_to::<market::OpenOrderData>() };
            assert!(head.is_empty(), "Data was not aligned");
            let open_order_data = &body[0];

            let tmp = open_order_data.orders;
            let mut x = tmp.to_vec();
            ids.append(& mut x);

        };

        let orders = self.request_open_orders_by_currency_pair(currency_pair).await?;

        for order in orders{
            if order.order_id == order_id{
                return Ok(Some(order));
            }
        }

        Ok(None)
    }

     /// Load data and keys of market
     async fn load_market_data(self: &Arc<Self>, market_id: &Pubkey, program_id: &Pubkey) -> Result<()>{
        
        let account_data = tokio::task::spawn_blocking({ 
            let id_clone = market_id.clone();
            let self_clone = self.clone();
            
            // println!("assign_market --> id thread for rpc call {}", thread_id::get());
            move || self_clone.rpc_client.get_account_data(&id_clone)
            
        }).await??;
        
        let words: Cow<[u64]> = helpers::remove_dex_account_padding(&account_data)?;
        let account_flags = Market::account_flags(&account_data)?;
        let state: MarketState = {
        if account_flags.intersects(AccountFlag::Permissioned) {
            let state = transmute_one_pedantic::<MarketStateV2>(transmute_to_bytes(&words))
                    .map_err(|e| e.without_src())?;
                    state.check_flags()?;
                    state.inner
        } else {
            let state = transmute_one_pedantic::<MarketState>(transmute_to_bytes(&words))
                    .map_err(|e| e.without_src())?;
                    state.check_flags()?;
                    state
                }
        };

        let own_adr = helpers::convert64_to_pubkey(state.own_address);
        // assert_eq!(
        //     &own_adr,
        //     &self.program_id
        // );
        assert_eq!(
            transmute_to_bytes(&identity(state.own_address)),
            market_id.as_ref()
        );

        let coin_mint_adr = helpers::convert64_to_pubkey(state.coin_mint);
        let pc_mint_adr = helpers::convert64_to_pubkey(state.pc_mint);
        let coin_vault_adr = helpers::convert64_to_pubkey(state.coin_vault);
        let pc_vault_adr = helpers::convert64_to_pubkey(state.pc_vault);
        let req_q_adr = helpers::convert64_to_pubkey(state.req_q);
        let event_q_adr = helpers::convert64_to_pubkey(state.event_q);
        let bids_adr = helpers::convert64_to_pubkey(state.bids);
        let asks_adr = helpers::convert64_to_pubkey(state.asks);

        let vault_signer_nonce = helpers::gen_vault_signer_key(state.vault_signer_nonce, market_id, &program_id)?;

        let coin_data = self.rpc_client.get_account_data(&coin_mint_adr)?;
        let coin_min_data = state::Mint::unpack_from_slice(&coin_data)?;

        let coin_data = self.rpc_client.get_account_data(&pc_mint_adr)?;
        let pc_mint_data = state::Mint::unpack_from_slice(&coin_data)?;

        self.markets.lock().insert(*market_id, market::MarketParsed{
            state,
            pc_decimal: pc_mint_data.decimals,
            coin_decimal: coin_min_data.decimals,
            own_adr,
            coin_mint_adr,
            pc_mint_adr,
            coin_vault_adr,
            pc_vault_adr,
            req_q_adr,
            event_q_adr, 
            bids_adr,
            asks_adr,
            vault_signer_nonce,
            coin_lot: state.coin_lot_size,
            pc_lot: state.pc_lot_size,
        });

        Ok(())
    }

    fn load_orders_for_owner(
        self: &Self,
        market_id: Pubkey,
    ) -> Result<Vec<(Pubkey, solana_sdk::account::Account)>>{
        let filter1 = rpc_filter::RpcFilterType::Memcmp(rpc_filter::Memcmp{
            offset: offset_of!(market::OpenOrderData, market),
            bytes: rpc_filter::MemcmpEncodedBytes::Binary(market_id.to_string()),
            encoding: None
        });
    
        let filter2 = rpc_filter::RpcFilterType::Memcmp(rpc_filter::Memcmp{
            offset: offset_of!(market::OpenOrderData, owner),
            bytes: rpc_filter::MemcmpEncodedBytes::Binary(self.payer().to_string()),
            encoding: None
        });

        let filter3 = rpc_filter::RpcFilterType::DataSize(size_of::<market::OpenOrderData>() as u64);

        let filters = Some(vec!(filter1, filter2, filter3));

        let account_config = rpc_config::RpcAccountInfoConfig {
            encoding: Some(solana_account_decoder::UiAccountEncoding::Base64),
            ..rpc_config::RpcAccountInfoConfig::default()
        };
    
        let with_context = Some(false);
    
        let config = rpc_config::RpcProgramAccountsConfig{
            filters,
            account_config, 
            with_context
        };
    
       let ret_vol =  self.rpc_client.get_program_accounts_with_config(&self.markets_adr[&market_id].program_id, config)?;
       Ok(ret_vol)
    }

    fn make_max_native (
        self: &Self,
        market_id: &Pubkey,
        price: u64, 
        size: u64) -> u64 {
        let market = &self.markets.lock()[market_id];
        market.state.pc_lot_size*size*price
    }
    
    fn make_price (
        self: &Self,
        market_id: &Pubkey,
        raw_price: Decimal,) -> Result<u64> {
        let market = &self.markets.lock()[market_id];
        let ret_vol = (raw_price * Decimal::from_u64(10u64.pow(market.pc_decimal as u32)).unwrap() * Decimal::from_u64(market.coin_lot).unwrap()) / 
        (Decimal::from_u64(10u64.pow(market.coin_decimal as u32)).unwrap() * Decimal::from_u64(market.state.pc_lot_size).unwrap());
        
        Ok(ret_vol.to_u64().unwrap())
    }
    
    fn make_size (
        self: &Self,
        market_id: &Pubkey,
        raw_size: Decimal) -> Result<u64> {
        let market = &self.markets.lock()[market_id];
        let ret_vol = raw_size * Decimal::from_u64(10u64.pow(market.coin_decimal as u32)).unwrap() /
        Decimal::from_u64(market.coin_lot).unwrap();

        Ok(ret_vol.to_u64().unwrap())
    }

    fn decod_price (
        self: &Self,
        market: &MarketParsed,
        raw_price: u64,
    ) -> Result<Decimal>{
        Ok((Decimal::from_u64(raw_price).unwrap() * Decimal::from_u64(10u64.pow(market.coin_decimal as u32)).unwrap() * Decimal::from_u64(market.state.pc_lot_size).unwrap()) /
            (Decimal::from_u64(10u64.pow(market.pc_decimal as u32)).unwrap() * Decimal::from_u64(market.coin_lot).unwrap()))
    }

    fn decode_size(
        self: &Self,
        market: &MarketParsed,
        raw_size: u64,
    ) -> Result<Decimal>{
        Ok(Decimal::from_u64(raw_size).unwrap() * Decimal::from_u64(market.coin_lot).unwrap() / 
            Decimal::from_u64(10u64.pow(market.coin_decimal as u32)).unwrap())
    }

}

pub fn find_pukey_by_currency_pair <'a> (map: &'a HashMap<Pubkey, market::MarketAdr>, currency_pair: &String) -> Option<(&'a Pubkey, &'a market::MarketAdr)> {
    
    for (key, val) in map{
        if val.name == *currency_pair && val.deprecated == false {
            return Some((key, val))
        }
    }
    
    None
}
