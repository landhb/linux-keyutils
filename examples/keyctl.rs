//! Example CLI application that allows you to interact
//! with the Linux kernel keyring from user space.
//!
//! Demo code for the linux_keyutils crate.
use clap::Parser;
use linux_keyutils::{Key, KeyRing, KeyRingIdentifier, KeySerialId};
use linux_keyutils::{KeyPermissionsBuilder, Permission};
use std::error::Error;
use zeroize::Zeroizing;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    subcommand: Command,
}

#[derive(clap::Subcommand, Debug, PartialEq)]
enum Command {
    /// Create a new key
    Create {
        #[clap(short, long)]
        description: String,

        #[clap(short, long)]
        secret: String,
    },
    /// Read the secret from a key
    Read {
        #[clap(short, long)]
        id: i32,
    },
    /// Change ownership of a key
    Chown {
        #[clap(short, long)]
        id: i32,

        #[clap(short, long)]
        uid: Option<u32>,

        #[clap(short, long)]
        gid: Option<u32>,
    },
    /// Change permissions of a key
    Chmod {
        #[clap(short, long)]
        id: i32,
    },
    /// Invalidate a key
    Invalidate {
        #[clap(short, long)]
        id: i32,
    },
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();

    // Obtain the default User keyring for the current UID/user
    // See [KeyRingIdentifier] and `man 2 keyctl` for more information on default
    // keyrings for processes.
    let ring = KeyRing::get_persistent(KeyRingIdentifier::User)?;

    _ = match args.subcommand {
        Command::Create {
            description,
            secret,
        } => {
            let key = ring.add_key(&description, &secret)?;
            println!("Created key with ID {:?}", key.get_id());
        }
        Command::Read { id } => {
            let key = Key::from_id(KeySerialId(id));
            let mut buf = Zeroizing::new([0u8; 2048]);
            let len = key.read(&mut buf)?;
            println!("Secret {:?}", std::str::from_utf8(&buf[..len])?);
        }
        Command::Chown { id, uid, gid } => {
            let key = Key::from_id(KeySerialId(id));
            key.chown(uid, gid)?;
        }
        Command::Chmod { id } => {
            let key = Key::from_id(KeySerialId(id));
            let perms = KeyPermissionsBuilder::builder()
                .user(Permission::ALL)
                .build();
            key.set_perm(perms)?;
        }
        Command::Invalidate { id } => {
            let key = Key::from_id(KeySerialId(id));
            key.invalidate()?;
        }
    };

    Ok(())
}
