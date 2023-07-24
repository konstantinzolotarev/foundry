use super::WalletTrait;
use clap::Parser;
use ethers::{signers::LocalWallet, types::Address};
use eyre::Result;
use serde::Serialize;

/// The wallet options can either be:
/// 1. Keystore (via keystore directory path)
#[derive(Parser, Debug, Default, Clone, Serialize)]
#[clap(next_help_heading = "Keystore Wallet options", about = None, long_about = None)]
pub struct KeystoreWallet {
    /// The sender account.
    #[clap(
        long,
        short,
        help_heading = "Wallet options - raw",
        value_name = "ADDRESS",
        env = "ETH_FROM"
    )]
    pub from: Option<Address>,

    /// Use the keystore in the given folder or file.
    #[clap(
        long = "keystore",
        help_heading = "Wallet options - keystore",
        value_name = "PATH",
        env = "ETH_KEYSTORE"
    )]
    pub keystore_path: Option<String>,

    /// The keystore password.
    ///
    /// Used with --keystore.
    #[clap(
        long = "password",
        help_heading = "Wallet options - keystore",
        requires = "keystore_path",
        value_name = "PASSWORD"
    )]
    pub keystore_password: Option<String>,

    /// The keystore password file path.
    ///
    /// Used with --keystore.
    #[clap(
        long = "password-file",
        help_heading = "Wallet options - keystore",
        requires = "keystore_path",
        value_name = "PASSWORD_FILE",
        env = "ETH_PASSWORD"
    )]
    pub keystore_password_file: Option<String>,
}

impl KeystoreWallet {
    /// Returns list of accounts from given keystore.
    pub fn accounts(&self) -> Result<Option<Vec<LocalWallet>>> {
        if let Some(path) = &self.keystore_path {
            let path = dunce::canonicalize(path)?;
            if !path.is_dir() {
                eyre::bail!("Keystore `{path:?}` have to be a directory");
            }
            let mut wallets = Vec::new();

            let password = self.get_password()?;

            if let Ok(entries) = path.read_dir() {
                for entry in entries.flatten().filter(|x| x.path().is_file()) {
                    match self.get_from_keystore(
                        Some(&entry.path().display().to_string()),
                        Some(&password),
                        None,
                    ) {
                        Ok(wallet) => wallets.push(wallet.unwrap()),
                        Err(_) => continue, // Just ignoring invalid files
                    }
                }
                return Ok(Some(wallets))
            } else {
                eyre::bail!("failed to access `{path:?}`");
            }
        }
        Ok(None)
    }

    fn get_password(&self) -> Result<String> {
        Ok(match (self.keystore_password.clone(), self.keystore_password_file.clone()) {
            (Some(password), _) => password.to_string(),
            (_, Some(password_file)) if !password_file.is_empty() => {
                self.password_from_file(password_file)?
            }
            _ => rpassword::prompt_password("Enter secret: ")?,
        })
    }
}

impl WalletTrait for KeystoreWallet {
    fn sender(&self) -> Option<Address> {
        self.from
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // #[test]
    // fn find_keystore() {
    //     let keystore = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/keystore");
    //     let keystore_file = keystore
    //         .join("UTC--2022-10-30T06-51-20.130356000Z--560d246fcddc9ea98a8b032c9a2f474efb493c28"
    // );     let wallet: Wallet = Wallet::parse_from([
    //         "foundry-cli",
    //         "--from",
    //         "560d246fcddc9ea98a8b032c9a2f474efb493c28",
    //     ]);
    //     let file = wallet.find_keystore_file(&keystore_file).unwrap();
    //     assert_eq!(file, keystore_file);
    // }

    // #[test]
    // fn illformed_private_key_generates_user_friendly_error() {
    //     let wallet = Wallet {
    //         from: None,
    //         interactive: false,
    //         private_key: Some("123".to_string()),
    //         keystore_path: None,
    //         keystore_password: None,
    //         keystore_password_file: None,
    //         mnemonic: None,
    //         mnemonic_passphrase: None,
    //         ledger: false,
    //         trezor: false,
    //         aws: false,
    //         hd_path: None,
    //         mnemonic_index: 0,
    //     };
    //     match wallet.private_key() {
    //         Ok(_) => {
    //             panic!("illformed private key shouldn't decode")
    //         }
    //         Err(x) => {
    //             assert!(
    //                 x.to_string().contains("Failed to create wallet"),
    //                 "Error message is not user-friendly"
    //             );
    //         }
    //     }
    // }

    // #[test]
    // fn gets_password_from_file() {
    //     let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    //         .join("tests/fixtures/keystore/password")
    //         .into_os_string();
    //     let wallet: Wallet = Wallet::parse_from(["foundry-cli"]);
    //     let password = wallet.password_from_file(path).unwrap();
    //     assert_eq!(password, "this is keystore password")
    // }
}
