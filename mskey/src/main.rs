mod cli;
mod keys;

use anyhow::{bail, Result};
use clap::Parser;
use keys::Bink;
use num_bigint::BigInt;
use num_traits::Num;
use umskt::{
    bink1998, bink2002, confid,
    crypto::{EllipticCurve, PrivateKey},
};

use crate::{cli::*, keys::load_keys};

fn main() -> Result<()> {
    let args = Cli::parse();

    if args.verbose {
        simple_logger::init_with_level(log::Level::Info)?;
    } else {
        simple_logger::init_with_level(log::Level::Warn)?;
    }

    match &args.command {
        Commands::List(args) => list(args),
        Commands::Generate(args) => generate(args),
        Commands::Validate(args) => validate(args),
        Commands::ConfirmationId(args) => confirmation_id(args),
    }
}

fn list(args: &ListArgs) -> Result<()> {
    let keys = load_keys(args.keys_path.as_ref())?;
    for (key, value) in keys.products.iter() {
        println!("{}: {:?}", key, value.bink);
    }

    println!("\n\n** Please note: any BINK ID other than 2E is considered experimental at this time **\n");
    Ok(())
}

fn generate(args: &GenerateArgs) -> Result<()> {
    if args.channel_id > 999 {
        bail!("Channel ID must be 3 digits or fewer");
    }

    let keys = load_keys(args.keys_path.as_ref())?;

    let bink_id = args.bink_id.to_ascii_uppercase();
    let bink = &keys.bink[&bink_id];

    println!("Using BINK ID {bink_id}, which applies to these products:");
    for (key, value) in keys.products.iter() {
        if value.bink.contains(&bink_id) {
            println!("    {}", key);
        }
    }

    // gen_order is the order of the generator G, a value we have to reverse -> Schoof's Algorithm.
    let gen_order = &bink.n;
    let gen_order = BigInt::from_str_radix(gen_order, 10).unwrap();

    // We cannot produce a valid key without knowing the private key k. The reason for this is that
    // we need the result of the function K(x; y) = kG(x; y).
    let private_key = &bink.private;
    let private_key = BigInt::from_str_radix(private_key, 10).unwrap();

    let curve = initialize_curve(bink, &bink_id)?;
    let private_key = PrivateKey::new(gen_order, private_key)?;

    if u32::from_str_radix(&bink_id, 16)? < 0x40 {
        if let Some(serial) = args.serial {
            if serial > 999999 {
                bail!("Serial number must be 6 digits or fewer");
            }
        }
        bink1998_generate(
            &curve,
            &private_key,
            args.channel_id,
            args.serial,
            args.count,
        )?;
    } else {
        if args.serial.is_some() {
            bail!("Serial numbers do not apply for BINK IDs >= 0x40");
        }
        bink2002_generate(&curve, &private_key, args.channel_id, args.count)?;
    }

    Ok(())
}

fn validate(args: &ValidateArgs) -> Result<()> {
    // We can validate any given key using the available public key: {p, a, b, G, K}.
    // No private key or gen_order is required.
    let keys = load_keys(args.keys_path.as_ref())?;
    let bink_id = args.bink_id.to_ascii_uppercase();

    println!("Using BINK ID {bink_id}, which applies to these products:");
    for (key, value) in keys.products.iter() {
        if value.bink.contains(&bink_id) {
            println!("    {}", key);
        }
    }

    let bink = &keys.bink[&bink_id];
    let curve = initialize_curve(bink, &bink_id)?;

    if u32::from_str_radix(&bink_id, 16)? < 0x40 {
        bink1998_validate(&curve, &args.key_to_check)?;
    } else {
        bink2002_validate(&curve, &args.key_to_check)?;
    }

    Ok(())
}

fn initialize_curve(bink: &Bink, bink_id: &str) -> Result<EllipticCurve> {
    let p = &bink.p;
    let a = &bink.a;
    let gx = &bink.g.x;
    let gy = &bink.g.y;
    let kx = &bink.public.x;
    let ky = &bink.public.y;

    log::info!("Elliptic curve parameters for BINK ID {bink_id}:\n{bink}");

    let p = BigInt::from_str_radix(p, 10).unwrap();
    let a = BigInt::from_str_radix(a, 10).unwrap();
    let gx = BigInt::from_str_radix(gx, 10).unwrap();
    let gy = BigInt::from_str_radix(gy, 10).unwrap();
    let kx = BigInt::from_str_radix(kx, 10).unwrap();
    let ky = BigInt::from_str_radix(ky, 10).unwrap();

    EllipticCurve::new(p, a, gx, gy, kx, ky)
}

fn bink1998_generate(
    curve: &EllipticCurve,
    private_key: &PrivateKey,
    channel_id: u32,
    serial: Option<u32>,
    count: u64,
) -> Result<()> {
    for _ in 0..count {
        let product_key = bink1998::ProductKey::new(curve, private_key, channel_id, serial, None)?;
        log::info!("{:#?}", product_key);
        println!("{product_key}");
    }
    Ok(())
}

fn bink2002_generate(
    curve: &EllipticCurve,
    private_key: &PrivateKey,
    channel_id: u32,
    count: u64,
) -> Result<()> {
    for _ in 0..count {
        let product_key = bink2002::ProductKey::new(curve, private_key, channel_id, None, None)?;
        log::info!("{:#?}", product_key);
        println!("{product_key}");
    }
    Ok(())
}

fn bink1998_validate(curve: &EllipticCurve, key: &str) -> Result<()> {
    let product_key = bink1998::ProductKey::from_key(curve, key)?;
    log::info!("{:#?}", product_key);
    println!("{product_key}");
    println!("Key validated successfully!");
    Ok(())
}

fn bink2002_validate(curve: &EllipticCurve, key: &str) -> Result<()> {
    let product_key = bink2002::ProductKey::from_key(curve, key)?;
    log::info!("{:#?}", product_key);
    println!("{product_key}");
    println!("Key validated successfully!");
    Ok(())
}

fn confirmation_id(args: &ConfirmationIdArgs) -> Result<()> {
    let confirmation_id = confid::generate(&args.instid)?;
    println!("Confirmation ID: {confirmation_id}");
    Ok(())
}
