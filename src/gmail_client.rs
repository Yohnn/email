use crate::cli::Args;
use crate::oauth;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use reqwest::{self, Error};
use serde::Deserialize;
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time;
use std::{fs, io::BufReader};
pub struct GmailClient {
    client: reqwest::blocking::Client,
    auth_header: String,
    user: String,
}

#[derive(Deserialize)]
struct Token {
    access_token: String,
    token_type: String,
    expires_in: u32,
    refresh_token: String,
    scope: String,
}

impl GmailClient {
    pub fn new(user: &String, token: &str) -> Self {
        let auth_header = "Bearer ".to_owned();
        let auth_header = auth_header + token;
        let gmail_client = GmailClient {
            client: reqwest::blocking::Client::new(),
            auth_header: auth_header,
            user: user.clone(),
        };
        return gmail_client;
    }
    pub fn new_from_cache(token_cache_path: &str, user: &String) -> GmailClient {
        let token_file = fs::File::open(token_cache_path);

        match token_file {
            Ok(token_content) => {
                println!("Existing token cache {token_cache_path} found.");
                let reader = BufReader::new(token_content);
                let token: Token = serde_json::from_reader(reader).unwrap();
                return self::GmailClient::new(user, &token.access_token);
            }
            Err(_) => {
                println!("No token cache {token_cache_path} found. Authenticating from web.");
                let gmail_client = self::GmailClient::auth_from_web(user);
                return gmail_client;
            }
        };
    }

    pub fn send_templated_email(&self, template: String, args: &Args) -> Result<String, Error> {
        let mut path = String::new();
        path.push_str(template.as_str());
        path.push_str(".txt");

        println!("Reading {}", path);
        let raw_email =
            fs::read_to_string(path).expect("Should be able to read raw email txt file");
        let raw_email = substitute_email_params(raw_email, &args);
        let req_body = raw_email;

        let req_url =
            "https://gmail.googleapis.com/upload/gmail/v1/users/{user}/messages/send".to_string();
        let req_url = req_url.replace("{user}", &self.user);

        let response = self
            .client
            .post(req_url)
            .header("Authorization", &self.auth_header)
            .header("Content-Type", "message/rfc822")
            .body(req_body)
            .send()
            .unwrap()
            .text();
        return response;
    }

    fn auth_from_web(user: &String) -> Self {
        /*
         * This follows the prescribed oauth flow for Desktop Apps from Google
         */
        let path = "credentials.json";
        let file = fs::File::open(path).expect("credentials.json should be present");
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
            .expect("Token should be extractable.");

        let token_path = "token.json";
        oauth::save_token(token_path.to_string(), &token_result);

        return self::GmailClient::new(user, token_result.access_token().secret());
    }
}

fn substitute_email_params(template: String, args: &Args) -> String {
    let template = template.clone();
    let template = template.replace("{user}", &args.user);
    let template = template.replace("{from}", &args.from);
    let template = template.replace("{to}", &args.to);
    let template = template.replace("{from_first_name}", &args.from_first_name);
    let template = template.replace("{contact_name}", &args.contact_name);

    return template;
}
