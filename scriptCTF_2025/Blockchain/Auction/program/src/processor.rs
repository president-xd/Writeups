use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint::ProgramResult,
    program::{invoke, invoke_signed},
    program_error::ProgramError,
    pubkey::Pubkey,
    rent::Rent,
    system_instruction,
};


use borsh::{BorshDeserialize, BorshSerialize};

#[repr(C)]
#[derive(BorshSerialize, BorshDeserialize)]
pub struct Config {
    pub first_bidder: Pubkey,
    pub has_bid: bool, 
}

#[repr(C)]
#[derive(BorshSerialize, BorshDeserialize)]
pub struct Winner {
    pub winner: Pubkey,
    pub bid: u64,
}
#[repr(C)]
#[derive(BorshSerialize, BorshDeserialize)]
pub struct BidderData {
    pub owner: Pubkey,
    pub bid: u64,
}
pub const ACCOUNT_SIZE: usize = 256;
pub fn initialize(program: &Pubkey, accounts: &[AccountInfo], config_bump: u8, vault_bump: u8, winner_bump: u8) -> ProgramResult {
    // Initialize: Set the first bidder, how much they bid, and winner of the auction
	let account_iter = &mut accounts.iter();
    let vault = next_account_info(account_iter)?;
    let user = next_account_info(account_iter)?;
    let config = next_account_info(account_iter)?;
    let winner = next_account_info(account_iter)?;
    assert!(user.is_signer);
    // Create PDAs via provided bump
    let Ok(config_pda) = Pubkey::create_program_address(&[b"INITIAL", &[config_bump]], &program) else { 
        return Err(ProgramError::InvalidSeeds); 
    };
    let Ok(vault_pda) = Pubkey::create_program_address(&[b"VAULT", &[vault_bump]], &program) else { 
        return Err(ProgramError::InvalidSeeds); 
    };
    let Ok(winner_pda) = Pubkey::create_program_address(&[b"WINNER", &[winner_bump]], &program) else { 
        return Err(ProgramError::InvalidSeeds); 
    };
    // check derived PDAs are the same as the ones provided
    if *config.key != config_pda {
        return Err(ProgramError::InvalidAccountData);
    }
    if *vault.key != vault_pda {
        return Err(ProgramError::InvalidAccountData);
    }
    if *winner.key != winner_pda {
        return Err(ProgramError::InvalidAccountData);
    }
    // Create PDAs
    invoke_signed(
        &system_instruction::create_account(
            user.key,
            &config_pda,
            Rent::minimum_balance(&Rent::default(), ACCOUNT_SIZE),
            ACCOUNT_SIZE as u64,
            &program,
        ),
        &[user.clone(), config.clone()],
        &[&[b"INITIAL", &[config_bump]]],
    )?;
    invoke_signed(
        &system_instruction::create_account(
            user.key,
            &vault_pda,
            Rent::minimum_balance(&Rent::default(), ACCOUNT_SIZE),
            ACCOUNT_SIZE as u64,
            &program,
        ),
        &[user.clone(), vault.clone()],
        &[&[b"VAULT", &[vault_bump]]],
    )?;
    invoke_signed(
        &system_instruction::create_account(
            user.key,
            &winner_pda,
            Rent::minimum_balance(&Rent::default(), ACCOUNT_SIZE),
            ACCOUNT_SIZE as u64,
            &program,
        ),
        &[user.clone(), winner.clone()],
        &[&[b"WINNER", &[winner_bump]]],
    )?;
    // Set signer of transaction as first bidder
    let configuration = Config {
        first_bidder: *user.key,
        has_bid: false,
    };
    // Current winner
    let win = Winner {
        winner: *program,
        bid: 0,
    };
     configuration.serialize(&mut &mut (*config.data).borrow_mut()[..]).unwrap();
     win.serialize(&mut &mut (*winner.data).borrow_mut()[..]).unwrap();
    Ok(())
}


pub fn initialize_bidder(program: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult { 
    // Your PDA to store your bidding data!
    let account_iter = &mut accounts.iter();
    let user = next_account_info(account_iter)?;
    let user_config = next_account_info(account_iter)?;
    let (user_config_pda, user_config_bump) = Pubkey::find_program_address(&[user.key.as_ref(), b"BIDDER"], program); // Each person has unique config
    assert!(user.is_signer);
    if *user_config.key != user_config_pda {
        return Err(ProgramError::InvalidAccountData);
    }
    // If PDA not initialize, create it
    if user_config.lamports() == 0 {
        let user_data = BidderData {
            owner: *user.key,
            bid: 0,
        };
        invoke_signed(
            &system_instruction::create_account(
            &user.key,
            &user_config.key,
            Rent::minimum_balance(&Rent::default(), ACCOUNT_SIZE),
           ACCOUNT_SIZE as u64,
           &program,
        ),
        &[user.clone(), user_config.clone()],
        &[&[user.key.as_ref(), b"BIDDER", &[user_config_bump]]],
        )?;
        user_data.serialize(&mut &mut (*user_config.data).borrow_mut()[..]).unwrap();
    }
    else { // PDA already initialized
        return Err(ProgramError::AccountAlreadyInitialized);
    }
    Ok(())


}


pub fn bid(program: &Pubkey, accounts: &[AccountInfo], vault_bump: u8, winner_bump: u8, amount: u64) -> ProgramResult {
    let account_iter = &mut accounts.iter();
    let user = next_account_info(account_iter)?;
    let user_config = next_account_info(account_iter)?;
    let config = next_account_info(account_iter)?;
    let vault = next_account_info(account_iter)?;
    let winner = next_account_info(account_iter)?;
    assert!(user.is_signer);

    let data = &mut BidderData::deserialize(&mut &(*user_config.data).borrow_mut()[..])?; 
    let config_data = &mut Config::deserialize(&mut &(*config.data).borrow_mut()[..])?; 
    let winner_data = &mut Winner::deserialize(&mut &(*winner.data).borrow_mut()[..])?; 

    assert_eq!(data.owner,*user.key); // Don't use someone else's PDA :(
    // Check if signer is first bidder or if first bidder has already bid
    if (config_data.first_bidder != *user.key) && (config_data.has_bid == false) {
        return Err(ProgramError::InvalidAccountData); 
    }
    // check derived PDAs are the same as the ones provided
    let Ok(vault_pda) = Pubkey::create_program_address(&[b"VAULT", &[vault_bump]], &program) else { 
        return Err(ProgramError::InvalidSeeds); 
    };
    let Ok(winner_pda) = Pubkey::create_program_address(&[b"WINNER", &[winner_bump]], &program) else { 
        return Err(ProgramError::InvalidSeeds); 
    };
    if *vault.key != vault_pda {
        return Err(ProgramError::InvalidAccountData);
    }
    if *winner.key != winner_pda {
        return Err(ProgramError::InvalidAccountData);
    }
    // Transfer from your account to the vault
    invoke(
    &system_instruction::transfer(
      &user.key,
      &vault_pda,
      amount,
    ),
    &[user.clone(), vault.clone()],
  )?;

    if amount > winner_data.bid { // Congrats you are the current winner
        winner_data.winner = *user.key;
        winner_data.bid = amount;
        winner_data.serialize(&mut &mut (*winner.data).borrow_mut()[..]).unwrap();
    }
    // If you are first bidder and have not bid yet, set has_bid to true
    if config_data.first_bidder == *user.key && (config_data.has_bid == false) {
        config_data.has_bid = true;
        config_data.serialize(&mut &mut (*config.data).borrow_mut()[..]).unwrap();
    }
    // Update your PDA with the correct bid amount
    data.bid += amount;
    data.serialize(&mut &mut (*user_config.data).borrow_mut()[..]).unwrap();

    Ok(())

}

