use clap::Parser;
use std::collections::HashMap;

#[derive(Parser, Debug, serde::Deserialize, serde:: Serialize)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(long)]
    pub template: String,
    #[arg(long)]
    pub from_name: String,
    #[arg(long)]
    pub to_email: String,
    #[arg(short, long)]
    pub from_email: String,
    #[arg(long)]
    pub from_first_name: String,
    #[arg(short, long)]
    pub to_contact_name: String,
}

pub fn get_args() -> Args {
    let args = Args::parse();

    let iterable_args: HashMap<String, String> =
        serde_json::from_value(serde_json::to_value(&args).unwrap()).unwrap();

    for (key, val) in &iterable_args {
        println!("{:?} : {:?}", key, val);
        if val == "" {
            panic!("Incomplete arguments. Must have {:?}", key);
        }
    }

    return args;
}
