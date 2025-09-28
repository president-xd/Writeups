#![cfg(not(feature = "no-entrypoint"))]

use solana_program::{
    account_info::AccountInfo,
    entrypoint,
    entrypoint::ProgramResult,
    pubkey::Pubkey,
};

use borsh::{
  BorshDeserialize,
  BorshSerialize,
};

use crate::processor:: {
  initialize,
  initialize_bidder,
  bid,
};

entrypoint!(process_instruction);

#[derive(BorshSerialize, BorshDeserialize)]
pub enum AuctionInstruction {
    Initialize { config_bump: u8, vault_bump: u8, winner_bump: u8},
    InitializeBidder { },
    Bid { vault_bump: u8, winner_bump: u8, amount: u64},
}

pub fn process_instruction(program: &Pubkey, accounts: &[AccountInfo], mut data: &[u8]) -> ProgramResult {
  match AuctionInstruction::deserialize(&mut data)? {
    AuctionInstruction::Initialize { config_bump, vault_bump, winner_bump } => initialize(program, accounts, config_bump,vault_bump, winner_bump),
    AuctionInstruction::InitializeBidder {  } => initialize_bidder(program, accounts),
    AuctionInstruction::Bid { vault_bump, winner_bump, amount} => bid(program, accounts,vault_bump, winner_bump, amount),
  }
}