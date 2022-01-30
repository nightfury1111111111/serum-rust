use serum_api::client::{Client, NetworkType};
use solana_sdk::{signature::Keypair};
use anyhow::{Context, Result, anyhow};
use std::sync::Arc;
use rust_decimal_macros::dec;

use std::{thread, time, error::Error};

pub fn get_user_keypair(path: &String) -> Result<Keypair> {
    println!("loading user1 keypair from {}", path);

    let user_keypair = solana_sdk::signature::read_keypair_file(path)
        .map_err(|e| anyhow!("{}", e))
        .context("unable to load program keypair")?;
    Ok(user_keypair)
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {

    let payr_path_1 = "./key_1.json".to_string();
    let payer_1 = get_user_keypair(&payr_path_1).unwrap();

    let payr_path_2 = "./key_2.json".to_string();
    let payer_2 = get_user_keypair(&payr_path_2).unwrap();

    let payr_path_2 = "./key_2.json".to_string();
    let payer_3 = get_user_keypair(&payr_path_2).unwrap();

    let markets_path = "./markets_dev.json".to_string();
    let markets_main_path = "./markets.json".to_string();

    let currency_pair  = "test3/test4".to_string();

    let devnet_client1 = Arc::new(Client::new(NetworkType::Devnet, payer_1, &markets_path)?);
    let devnet_client2 = Arc::new(Client::new(NetworkType::Devnet, payer_2, &markets_path)?);
    let mainnet_client = Arc::new(Client::new(NetworkType::Mainnet, payer_3, &markets_main_path)?);

    
    devnet_client1.print_keys(&currency_pair).await?;

    println!("Initial order State:\n");
    let orders = devnet_client1.request_open_orders().await.unwrap();
    if orders.len() == 0 {
        println!("This market have not open orders!")
    } else {
        for order in &orders {
        println!("{:#?}", order);
        }
    }
    
    devnet_client1.create_order(
        &currency_pair, 
        serum_dex::matching::Side::Bid, 
        dec!(1), 
        dec!(2), 
        serum_dex::matching::OrderType::Limit
    ).await?;

    thread::sleep(time::Duration::from_secs(60));

    println!("\t *** Payer 1*** \n");
    println!("\t After placing (Bids) orders by client 1 ...");

    let orders = devnet_client1.request_open_orders().await?;
    if orders.len() == 0 {
        println!("This market have not open orders!")
    } else {
        for order in &orders {
        println!("{:#?}", order);
        }
    }

    println!("\t *** Payer 2*** \n");

    devnet_client2.create_order(
        &currency_pair, 
        serum_dex::matching::Side::Ask, 
        dec!(1), 
        dec!(2), 
        serum_dex::matching::OrderType::Limit).await.unwrap();

    thread::sleep(time::Duration::from_secs(15));

    println!("\t After placing (Asks) orders by client 2 ... ");
    
    let orders = devnet_client2.request_open_orders().await.unwrap();
    if orders.len() == 0 {
        println!("This market have not open orders!")
    } else {
        for order in &orders {
        println!("{:#?}", order);
        }
    }

    devnet_client1.settle_funds(&currency_pair).await?;
    thread::sleep(time::Duration::from_secs(15));
    devnet_client2.settle_funds(&currency_pair).await?;
    thread::sleep(time::Duration::from_secs(15));

    devnet_client1.cancel_all_orders(&currency_pair).await?;
    devnet_client2.cancel_all_orders(&currency_pair).await?;
    thread::sleep(time::Duration::from_secs(60));

    println!("\n \t  MainNet Part \n");
    println!("\n \t ***BTC\\USDC Market*** \n");
    
    let orders = mainnet_client.request_open_orders().await.unwrap();
    if orders.len() == 0 {
        println!("This market have not open orders!")
    } else {
        for order in &orders {
        println!("{:#?}", order);
        }
    }

    println!("Done");
    Ok(())
}
