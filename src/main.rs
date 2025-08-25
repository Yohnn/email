mod cli;
mod gmail_client;
mod oauth;

fn main() {
    let args = cli::get_args();
    let token_file = "token.json";
    let user = args.from_email.clone();
    let client = gmail_client::GmailClient::new_from_cache(token_file, &user);
    let template = args.template.clone();
    let response = client.send_templated_email(template.to_owned(), &args);

    match response {
        Ok(r) => {
            if r.contains("error") {
                println!("Failed to send email with error: {:?}", r)
            } else {
                println!("Successfully sent email!")
            }
        }
        Err(e) => println!("Failed to send email with error: {:?}", e),
    }
}
