use clap::Parser;
use oauth2::basic::BasicClient;
use oauth2::{
    AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, PkceCodeChallenge, RedirectUrl,
    Scope, TokenResponse, TokenUrl,
};
use reqwest;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self};
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

#[derive(Deserialize, Debug)]
struct AuthResult {
    code: String,
}

#[derive(Parser, Debug, serde::Deserialize, serde:: Serialize)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(long)]
    template: String,
    #[arg(long)]
    from: String,
    #[arg(long)]
    to: String,
    #[arg(short, long)]
    user: String,
    #[arg(long)]
    from_first_name: String,
    #[arg(short, long)]
    contact_name: String,
}

fn main() {
    let args = Args::parse();

    let iterable_args: HashMap<String, String> =
        serde_json::from_value(serde_json::to_value(&args).unwrap()).unwrap();

    for (key, val) in &iterable_args {
        println!("{:?} : {:?}", key, val);
        if val == "" {
            panic!("Incomplete arguments. Must have {:?}", key);
        }
    }

    let path = "credentials.json";
    let file = fs::File::open(path).unwrap();
    let reader = BufReader::new(file);

    let credentials: CredentialsFile = serde_json::from_reader(reader).unwrap();

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
                match handle_auth(stream, csrf_token_copy) {
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
    let raw_email = substitute_email_params(raw_email, &args);
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

fn handle_auth(stream: TcpStream, csrf_token: CsrfToken) -> Option<AuthResult> {
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
        return None;
    }

    if !parts[1].starts_with("/authcallback") {
        return None;
    }

    // oauth information is in url, we parse the url
    let url = parts[1];
    let query_pairs = parse_url(url);
    println!("Query pairs {:?}", query_pairs);

    // verify state is the same as the csrf token

    if query_pairs.get("state").unwrap() != csrf_token.secret() {
        return_response("HTTP/1.1 403 FORBIDDEN", &stream, "403.html");
        return None;
    }

    return_response("HTTP/1.1 200 OK", &stream, "auth_success.html");

    let auth_result: AuthResult = AuthResult {
        code: query_pairs.get("code").unwrap().to_string(),
    };
    return Some(auth_result);
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

fn substitute_email_params(template: String, args: &Args) -> String {
    let template = template.clone();
    let template = template.replace("{user}", &args.user);
    let template = template.replace("{from}", &args.from);
    let template = template.replace("{to}", &args.to);
    let template = template.replace("{from_first_name}", &args.from_first_name);
    let template = template.replace("{contact_name}", &args.contact_name);

    return template;
}
