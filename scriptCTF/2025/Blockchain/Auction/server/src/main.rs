use std::fs;
use std::io::Write;

use sol_ctf_framework::ChallengeBuilder;

use solana_program_test::tokio;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::signer::keypair::Keypair;
use std::error::Error;

use std::net::{TcpListener, TcpStream};

use auction::{
    initialize,
    initialize_bidder,
    bid,
};


use solana_sdk::account::Account;
use solana_program::system_program;
use borsh::{
  BorshDeserialize,
  BorshSerialize,
};

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Config {
    pub first_bidder: Pubkey,
    pub has_bid: bool, 
    pub highest_bidder: Pubkey,
    pub highest_bidder_bid: u64,
}

#[derive(BorshSerialize, BorshDeserialize)]
pub struct Winner {
    pub winner: Pubkey,
    pub bid: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let listener = TcpListener::bind("0.0.0.0:1337")?;

    println!("starting server at port 1337!");

    for stream in listener.incoming() {
        let stream = stream.unwrap();

        tokio::spawn(async {
            if let Err(err) = handle_connection(stream).await {
                println!("error: {:?}", err);
            }
        });
    }
    Ok(())
}

    

async fn handle_connection(mut socket: TcpStream) -> Result<(), Box<dyn Error>> {
    let mut builder = ChallengeBuilder::try_from(socket.try_clone().unwrap()).unwrap();
    // Load challenge
    let program_key = Pubkey::new_unique();
    let program_pubkey = builder.add_program(&"./chall.so", Some(program_key)).expect("Duplicate pubkey supplied");
    // Load solve
    let solve_pubkey = match builder.input_program() {
        Ok(pubkey) => pubkey,
        Err(e) => {
            writeln!(socket, "Error: cannot add solve program → {e}")?;
            return Ok(());
        }
    };
    // Create non-PDA accounts
    let noobmaster = Keypair::new();
        builder
        .builder
        .add_account(noobmaster.pubkey(), Account::new(5_000_000_000, 0, &system_program::ID)); // NoobMaster gets 5 SOL

    let user = Keypair::new();
        builder
        .builder
        .add_account(user.pubkey(), Account::new(1_000_000_000, 0, &system_program::ID)); // You get 1 SOL
    // Create PDA accounts
    let (config_addr, config_bump) = Pubkey::find_program_address(&["INITIAL".as_bytes()], &program_pubkey);

    let (vault_addr, vault_bump) = Pubkey::find_program_address(&["VAULT".as_bytes()], &program_pubkey);

    let (winner_addr, winner_bump) = Pubkey::find_program_address(&["WINNER".as_bytes()], &program_pubkey);



    let mut challenge = builder.build().await;
    // Provide essential data
    writeln!(socket, "program: {}", program_pubkey)?;
    writeln!(socket, "user: {}", user.pubkey())?;
    writeln!(socket, "noobmaster: {}", noobmaster.pubkey())?;
    // Initialize 
    challenge.run_ixs_full(
        &[initialize(program_pubkey, vault_addr, noobmaster.pubkey(), config_addr, winner_addr, config_bump, vault_bump, winner_bump)],
        &[&noobmaster],
        &noobmaster.pubkey(),
    ).await.ok();

    // You go first! But beware, NoobMaster always wins!
    let ixs = challenge.read_instruction(solve_pubkey).unwrap();
    challenge.run_ixs_full(
        &[ixs],
        &[&user],
        &user.pubkey(),
    ).await.ok();

    // Initialize Bidder: NoobMaster
    let (noobmaster_config_pda, _) = Pubkey::find_program_address(&[noobmaster.pubkey().as_ref(), b"BIDDER"], &program_pubkey);
    challenge.run_ixs_full(
        &[initialize_bidder(program_pubkey, noobmaster.pubkey(), noobmaster_config_pda)],
        &[&noobmaster],
        &noobmaster.pubkey(),
    ).await.ok();
    // Bid 4 SOL 
    challenge.run_ixs_full(
        &[bid(program_pubkey, noobmaster.pubkey(), noobmaster_config_pda, config_addr, vault_addr, winner_addr, vault_bump, winner_bump, 4_000_000_000)],
        &[&noobmaster],
        &noobmaster.pubkey(),
    ).await.ok();
    // Check winner
        let account = challenge.ctx.banks_client.get_account(winner_addr).await.unwrap().unwrap();
        let mut data: &[u8] = &account.data;
        let winner = Winner::deserialize(&mut data).unwrap().winner;

        if winner == user.pubkey() {
             let flag = fs::read_to_string("flag.txt").unwrap();
             writeln!(socket, "You beat NoobMaster? How is that even possible? Have a flag, 1337 h4x0r: {}", flag)?;
        }

    Ok(())

} 
