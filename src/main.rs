use core::panic;
use oauth2::basic::BasicClient;
use oauth2::reqwest;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use open;
use serde::Deserialize;
use std::io::{BufRead, BufReader};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::Sender;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::{fs, time};

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
    Timeout,
    Success,
}

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

    // let auth_thread = thread::Builder()::new().name("auth".to_string()).spawn(move || {
    //     let (auth_url, csrf_token) = client
    //         .authorize_url(CsrfToken::new_random)
    //         // Set the desired scopes.
    //         .add_scope(Scope::new(
    //             "https://www.googleapis.com/auth/gmail.readonly".to_string(),
    //         ))
    //         // Set the PKCE code challenge.
    //         .set_pkce_challenge(pkce_challenge)
    //         .url();

    //     // This is the URL you should redirect the user to, in order to trigger the authorization
    //     // process.
    //     println!("Opening: {}", auth_url);
    //     open::that(auth_url.to_string()).unwrap();
    // });

    let (tx_auth, rx_auth) = mpsc::channel();
    let (tx_timeout, rx_timeout) = mpsc::channel();

    let tx_auth_listener = tx_auth.clone();
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    start_timeout_countdown(tx_auth, rx_timeout, 10000);

    let listener_thread = thread::Builder::new()
        .name("listener".to_string())
        .spawn(move || {
            for stream in listener.incoming() {
                let stream = stream.unwrap();
                let tx_handler = tx_auth_listener.clone();
                handle_connection(stream, tx_handler);
            }
        })
        .unwrap();

    let listener_result = match listener_thread.join() {
        Ok(a) => println!("{:?}", a),
        error => println!("{:?}", error),
    };

    let receiver_thread = thread::Builder::new()
        .name("receiver".to_string())
        .spawn(move || {
            for received in rx_auth {
                match received {
                    AuthResult::Timeout => {
                        panic!("Timeout reached for authentication. Closing program.")
                    }
                    AuthResult::Success => {
                        println!("Authorization success!");
                        break;
                    }
                }
            }
        })
        .unwrap();

    // auth_thread.join().unwrap();
}

fn start_timeout_countdown(tx: Sender<AuthResult>, rx: mpsc::Receiver<AuthResult>, timeout: u64) {
    let r = match thread::Builder::new()
        .name("timeout".to_string())
        .spawn(move || {
            let timeout_duration = time::Duration::from_millis(timeout);
            thread::sleep(timeout_duration);
            let timeout_message = match rx.recv_timeout(timeout_duration) {
                Ok(a) => return,
                RecvTimeoutError => tx.send(AuthResult::Timeout).unwrap(),
            };
        }) {
        Ok(a) => println!("{:?}", a),
        error => println!("{:?}", error),
    };
}

fn handle_connection(mut stream: TcpStream, tx: Sender<AuthResult>) {
    let buf_reader = BufReader::new(&stream);
    // let request_line = buf_reader.lines().next().unwrap().unwrap();
    let request_line = match buf_reader.lines().next() {
        Some(a) => match a {
            Ok(b) => b,
            _ => return,
        },
        None => return,
    };
    let (status_line, filename) = if request_line == "GET /authcallback HTTP/1.1" {
        tx.send(AuthResult::Success).unwrap();
        ("HTTP/1.1 200 OK", "auth_success.html")
    } else {
        ("HTTP/1.1 404 NOT FOUND", "404.html")
    };

    let contents = fs::read_to_string(filename).unwrap();
    let length = contents.len();

    let response = format!("{status_line}\r\nContent-Length: {length}\r\n\r\n{contents}");

    stream.write_all(response.as_bytes()).unwrap();
}
