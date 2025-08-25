use oauth2::CsrfToken;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::io::{BufRead, BufReader};
use std::net::TcpStream;

#[derive(Deserialize, Debug)]
pub struct InstalledCredentials {
    pub client_id: String,
    pub client_secret: String,
    pub auth_uri: String,
    pub token_uri: String,
    pub redirect_uris: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct CredentialsFile {
    pub installed: InstalledCredentials,
}

#[derive(Deserialize, Debug)]
pub struct AuthResult {
    pub code: String,
}

pub fn handle_auth(stream: TcpStream, csrf_token: CsrfToken) -> Option<AuthResult> {
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
