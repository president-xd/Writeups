mod entrypoint;
pub mod processor;

use borsh::{
  BorshDeserialize,
  BorshSerialize,
  to_vec,
};

use solana_program::{
  instruction::{
    AccountMeta,
    Instruction,
  },
  system_program,
  pubkey::Pubkey,
};

#[derive(BorshSerialize, BorshDeserialize)]
pub enum AuctionInstruction {
    Initialize { config_bump: u8, vault_bump: u8, winner_bump: u8},
    InitializeBidder { },
    Bid { vault_bump: u8, winner_bump: u8, amount: u64},
}


pub fn initialize(program: Pubkey, vault: Pubkey, user: Pubkey, config: Pubkey, winner: Pubkey, config_bump: u8, vault_bump: u8, winner_bump: u8) -> Instruction {
	Instruction {
		program_id: program,
		accounts: vec![
		AccountMeta::new(vault, false),
		AccountMeta::new(user, true),
		AccountMeta::new(config, false),
		AccountMeta::new(winner, false),
		AccountMeta::new_readonly(system_program::id(), false),
		],
		 data: to_vec(&AuctionInstruction::Initialize { config_bump,vault_bump, winner_bump }).unwrap(),
	}
}


pub fn initialize_bidder(program: Pubkey, user: Pubkey, user_config: Pubkey,) -> Instruction {
	Instruction {
		program_id: program,
		accounts: vec![
		AccountMeta::new(user, true),
		AccountMeta::new(user_config, false),
		AccountMeta::new_readonly(system_program::id(), false),
		],
		 data: to_vec(&AuctionInstruction::InitializeBidder {  }).unwrap(),
	}
}


pub fn bid(program: Pubkey, user: Pubkey, user_config: Pubkey, config: Pubkey, vault: Pubkey, winner: Pubkey, vault_bump: u8, winner_bump: u8, amount: u64) -> Instruction {
	Instruction {
		program_id: program,
		accounts: vec![
		AccountMeta::new(user, true),
		AccountMeta::new(user_config, false),
		AccountMeta::new(config, false),
		AccountMeta::new(vault, false),
		AccountMeta::new(winner, false),
		AccountMeta::new_readonly(system_program::id(), false),
		],
		 data: to_vec(&AuctionInstruction::Bid { vault_bump, winner_bump, amount }).unwrap(),
	}
}