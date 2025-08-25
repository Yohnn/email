use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use reqwest;
use std::fs;
use std::io::BufReader;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time;
mod cli;
mod email;
mod oauth;

fn main() {
    let args = cli::get_args();

    let path = "credentials.json";
    let file = fs::File::open(path).unwrap();
    let reader = BufReader::new(file);

    let credentials: oauth::CredentialsFile = serde_json::from_reader(reader).unwrap();

    let client = BasicClient::new(ClientId::new(credentials.installed.client_id.to_string()))
        .set_client_secret(ClientSecret::new(
            credentials.installed.client_secret.to_string(),
        ))
        .set_auth_uri(AuthUrl::new(credentials.installed.auth_uri.to_string()).unwrap())
        .set_redirect_uri(
            RedirectUrl::new(credentials.installed.redirect_uris[0].to_string()).unwrap(),
        )
        .set_token_uri(TokenUrl::new(credentials.installed.token_uri.to_string()).unwrap());
    // Generate a PKCE challenge.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new(
            google_gmail1::api::Scope::Send.as_ref().to_string(),
        ))
        .add_scope(Scope::new(
            google_gmail1::api::Scope::Readonly.as_ref().to_string(),
        ))
        .set_pkce_challenge(pkce_challenge)
        .url();

    thread::Builder::new()
        .name("auth".to_string())
        .spawn(move || {
            // This is the URL you should redirect the user to, in order to trigger the authorization
            // process.
            println!("Opening: {}", &auth_url);
            open::that(auth_url.to_string()).unwrap();
        })
        .unwrap();

    let (tx_auth, rx_auth) = mpsc::channel();

    thread::Builder::new()
        .name("await_auth".to_string())
        .spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:7878").unwrap();

            for stream in listener.incoming() {
                let stream = stream.unwrap();
                let csrf_token_copy = csrf_token.clone();
                match oauth::handle_auth(stream, csrf_token_copy) {
                    Some(ar) => {
                        tx_auth.send(ar).unwrap();
                        break;
                    }
                    None => continue,
                }
            }
        })
        .unwrap();

    let max_timeout: time::Duration = time::Duration::from_millis(10000);

    println!("Awaiting authorization...");

    let ar = match rx_auth.recv_timeout(max_timeout) {
        Ok(ar) => {
            println!("Authorization successful, proceeding to program...");
            ar
        }
        Err(_) => panic!("Failed to authorize within given time! Please try again."),
    };

    let http_client = reqwest::blocking::ClientBuilder::new()
        // Following redirects opens the client up to SSRF vulnerabilities.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("Client should build");

    // Now you can trade it for an access token.
    let token_result = client
        .exchange_code(AuthorizationCode::new(ar.code.to_string()))
        // Set the PKCE code verifier.
        .set_pkce_verifier(pkce_verifier)
        .request(&http_client)
        .unwrap();

    let mut path = String::new();
    path.push_str(&args.template);
    path.push_str(".txt");

    println!("Reading {}", path);
    let raw_email = fs::read_to_string(path).expect("Should be able to read raw email txt file");
    let raw_email = email::substitute_email_params(raw_email, &args);
    let req_body = raw_email;

    println!("Sending email...");
    let mut authorization_header = String::new();
    authorization_header.push_str("Bearer");
    authorization_header.push_str(" ");
    authorization_header.push_str(token_result.access_token().secret());

    let req_url =
        "https://gmail.googleapis.com/upload/gmail/v1/users/{user}/messages/send".to_string();
    let req_url = req_url.replace("{user}", &args.user);

    let client = reqwest::blocking::Client::new();

    let response = client
        .post(req_url)
        .header("Authorization", authorization_header)
        .header("Content-Type", "message/rfc822")
        .body(req_body)
        .send()
        .unwrap()
        .text();

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
