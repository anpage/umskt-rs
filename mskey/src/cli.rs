use clap::{Args, Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, about, version, long_about = None)]
pub struct Cli {
    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Clone, Debug)]
pub enum Commands {
    /// Show which products/binks can be loaded
    #[command(visible_alias = "l")]
    List(ListArgs),
    /// Generate new product keys
    #[command(visible_alias = "g")]
    Generate(GenerateArgs),
    /// Validate a product key
    #[command(visible_alias = "v")]
    Validate(ValidateArgs),
    /// Generate a phone activation Confirmation ID from an Installation ID
    #[command(name = "confid", visible_alias = "c")]
    ConfirmationId(ConfirmationIdArgs),
}

#[derive(Args, Clone, Debug)]
pub struct ListArgs {
    /// Optional path to load a keys.json file
    #[arg(short, long = "keys")]
    pub keys_path: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct GenerateArgs {
    /// Which BINK identifier to use
    #[arg(short, long = "bink", default_value = "2E")]
    pub bink_id: String,

    /// Channel Identifier to use
    #[arg(short, long = "channel", default_value = "640")]
    pub channel_id: u32,

    /// Number of keys to generate
    #[arg(short = 'n', long = "number", default_value = "1")]
    pub count: u64,

    /// Serial number to use in the product ID (if applicable)
    #[arg(short, long)]
    pub serial: Option<u32>,

    /// Optional path to load a keys.json file
    #[arg(short, long = "keys")]
    pub keys_path: Option<String>,

    /// Whether to generate "upgrade" keys
    #[arg(short, long = "upgrade", default_value = "false")]
    pub upgrade: bool,
}

#[derive(Args, Clone, Debug)]
pub struct ValidateArgs {
    /// Which BINK identifier to use
    #[arg(short, long = "bink")]
    pub bink_id: Option<String>,

    /// Optional path to load a keys.json file
    #[arg(short, long = "keys")]
    pub keys_path: Option<String>,

    /// The Product key to validate, with or without hyphens
    pub key_to_check: String,
}

#[derive(Args, Clone, Debug)]
pub struct ConfirmationIdArgs {
    /// The Installation ID used to generate the Confirmation ID
    #[arg(name = "INSTALLATION_ID")]
    pub instid: String,
}
