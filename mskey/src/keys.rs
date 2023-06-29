use std::{collections::HashMap, fmt::Display, fs::File, io::BufReader, path::Path};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{from_reader, from_str};

pub fn load_keys<P: AsRef<Path> + std::fmt::Display>(path: Option<P>) -> Result<Keys> {
    let keys = {
        if let Some(path) = path {
            let file = File::open(&path)?;
            let reader = BufReader::new(file);
            let keys: Keys = from_reader(reader)?;

            log::info!("Loaded keys from {}", path);

            keys
        } else {
            from_str(std::include_str!("../../keys.json"))?
        }
    };

    Ok(keys)
}

#[derive(Serialize, Deserialize)]
pub struct Keys {
    #[serde(rename = "Products")]
    pub products: HashMap<String, Product>,
    #[serde(rename = "BINK")]
    pub bink: HashMap<String, Bink>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Product {
    #[serde(rename = "BINK")]
    pub bink: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Bink {
    pub p: String,
    pub a: String,
    pub b: String,
    pub g: Point,
    #[serde(rename = "pub")]
    pub public: Point,
    pub n: String,
    #[serde(rename = "priv")]
    pub private: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Point {
    pub x: String,
    pub y: String,
}

impl Display for Bink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, " P: {}", self.p)?;
        writeln!(f, " a: {}", self.a)?;
        writeln!(f, " b: {}", self.b)?;
        writeln!(f, "Gx: {}", self.g.x)?;
        writeln!(f, "Gy: {}", self.g.y)?;
        writeln!(f, "Kx: {}", self.public.x)?;
        writeln!(f, "Ky: {}", self.public.y)?;
        writeln!(f, " n: {}", self.n)?;
        writeln!(f, " k: {}", self.private)?;
        Ok(())
    }
}
