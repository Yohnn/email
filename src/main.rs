use oauth2::basic::BasicClient;
// use oauth2::reqwest;
use oauth2::{
    AuthUrl, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl, Scope, TokenUrl,
};
// use open;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Sender};
use std::thread;
use std::time;

#[derive(Deserialize, Debug)]
struct InstalledCredentials {
    client_id: String,
    client_secret: String,
    auth_uri: String,
    token_uri: String,
    redirect_uris: Vec<String>,
}

#[derive(Deserialize, Debug)]
struct CredentialsFile {
    installed: InstalledCredentials,
}

enum AuthResult {
    Success,
}

/*
1. Prompt auth -> starts and opens authorization

2. Auth Awaiter (receives auth event, sends auth event)
    start await auth flow
    start endpoint and listen... {
        process requests
        if request is good auth {
            send stop timeout
            end thread
        }
        else {
            do nothing
    }
    }




*/

fn main() {
    let path: &str = "credentials.json";
    let file = fs::File::open(path).unwrap();
    let reader = BufReader::new(file);

    let credentials: CredentialsFile = serde_json::from_reader(reader).unwrap();
    println!("{:?}", credentials);

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

    let auth_thread = thread::Builder::new()
        .name("auth".to_string())
        .spawn(move || {
            let (auth_url, csrf_token) = client
                .authorize_url(CsrfToken::new_random)
                // Set the desired scopes.
                .add_scope(Scope::new(
                    "https://www.googleapis.com/auth/gmail.readonly".to_string(),
                ))
                // Set the PKCE code challenge.
                .set_pkce_challenge(pkce_challenge)
                .url();

            // This is the URL you should redirect the user to, in order to trigger the authorization
            // process.
            println!("Opening: {}", auth_url);
            println!("Must verify against csrf token: {:?}", csrf_token.secret());
            open::that(auth_url.to_string()).unwrap();
        });

    let (tx_auth, rx_auth) = mpsc::channel();

    let tx_auth_listener = tx_auth.clone();

    let await_auth_thread = thread::Builder::new()
        .name("await_auth".to_string())
        .spawn(move || {
            let listener = TcpListener::bind("127.0.0.1:7878").unwrap();

            for stream in listener.incoming() {
                let stream = stream.unwrap();
                let tx_handler = tx_auth_listener.clone();
                let is_auth_success: bool = handle_auth(stream, tx_handler);
                if is_auth_success {
                    tx_auth.send(AuthResult::Success).unwrap();
                    break;
                }
            }
        })
        .unwrap();

    let max_timeout: time::Duration = time::Duration::from_millis(120000);

    println!("Awaiting authorization...");
    match rx_auth.recv_timeout(max_timeout) {
        Ok(_) => println!("Authorization successful, proceeding to program..."),
        Err(_) => panic!("Failed to authorize within given time! Please try again."),
    }
}

fn handle_auth(stream: TcpStream, tx: Sender<AuthResult>) -> bool {
    let mut buf_reader = BufReader::new(&stream);
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).unwrap();

    // Parse request line (e.g., "POST /path HTTP/1.1")
    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
    println!("{:?}", parts);
    if parts.len() < 3 || parts[0] != "GET" {
        println!(
            "Invalid HTTP Method received. Got {:?}. Must be GET.",
            parts[0]
        );
        return_response("HTTP/1.1 404 NOT FOUND", &stream, "404.html");
        return false;
    }

    if !parts[1].starts_with("/authcallback") {
        return false;
    }

    // oauth information is in url, we parse the url
    let url = parts[1];
    let query_pairs = parse_url(url);
    println!("Query pairs {:?}", query_pairs);
    return_response("HTTP/1.1 200 OK", &stream, "auth_success.html");

    tx.send(AuthResult::Success).unwrap();
    return false;
}

fn parse_url(url: &str) -> HashMap<&str, &str> {
    let query: Vec<&str> = url.split("?").collect();

    let query_parts: Vec<&str> = query[1].split("&").collect();
    let mut query_pairs = HashMap::new();
    for part in query_parts {
        let query_pair: Vec<&str> = part.split("=").collect();
        query_pairs.insert(query_pair[0], query_pair[1]);
    }
    return query_pairs;
}

fn return_response(status_line: &str, mut stream: &TcpStream, html_file: &str) {
    let status_line = status_line.to_string();
    let contents = fs::read_to_string(html_file).unwrap();
    let length = contents.len();
    let response = format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{contents}");
    stream.write_all(response.as_bytes()).unwrap();
}
