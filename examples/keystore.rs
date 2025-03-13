//! Example CLI app that creates, writes, reads, examines, and deletes an entry
//! in the keyutils keystore using APIs from the keyring crate.
//!
//! This example must be compiled with the keystore feature specified.

use keyring::{set_default_credential_builder, Entry};

fn main() {
    set_default_credential_builder(linux_keyutils::default_credential_builder());
    let service = "service";
    let username = "user";
    let password = "<PASSWORD>";
    let entry = Entry::new(service, username).unwrap();
    entry.set_password(password).unwrap();
    let retrieved = entry.get_password().unwrap();
    if retrieved != password {
        panic!("Passwords do not match");
    }
    println!("Entry: {:?}", entry);
    entry.delete_credential().unwrap()
}
