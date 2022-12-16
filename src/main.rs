use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use regex::Regex;
use reqwest::{Error, Response};
use serde_json::{Result, Value};
use colored::Colorize;

#[tokio::main]
async fn main() {
    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();

    ctrlc::set_handler(move || {
        println!("Stopping...");
        r.store(false, Ordering::SeqCst);
    }).expect("Error setting Ctrl-C handler");

    let credentials = get_password();
    let summoner_name = get_current_summoner(&credentials).await.unwrap();

    print!("{}", "Detected League Client logged into account ".green());
    println!("{}", summoner_name.green());
    println!("Starting to watch for deaths in ARAM. Will let you know to use the portal to get back into the action :)");
    println!("Use {} to exit any time.", "Ctrl+C".red());

    while running.load(Ordering::SeqCst) {
        watch_game_state(&credentials, &*summoner_name).await.expect("This shouldn't happen");
        std::thread::sleep(std::time::Duration::from_secs(3));
    }
    println!("Application stopped.");
}

async fn watch_game_state(credentials: &Credentials, summoner_name: &str) -> Result<()> {
    let is_playing_aram = is_currently_playing_aram(credentials).await.unwrap();
    if !is_playing_aram {
        // println!("Not playing ARAM.");
        return Ok(())
    }

    let url = "https://127.0.0.1:2999/liveclientdata/playerlist";
    let req = request_client_api(credentials, url).await;
    match req {
        Ok(res) => {
            let res_text = res.text().await.unwrap();
            let json: Value = serde_json::from_str(&*res_text)?;
            handle_active_game(json, summoner_name);
        }
        Err(_error) => {
            // this shouldn't happen, because it (usually) only fails if no game is active,
            // and that case is checked in is_currently_playing_aram
        }
    }
    Ok(())
}

async fn is_currently_playing_aram(credentials: &Credentials) -> Result<bool> {
    let url = "https://127.0.0.1:2999/liveclientdata/gamestats";
    let req = request_client_api(credentials, url).await;
    match req {
        Ok(res) => {
            let res_text = res.text().await.unwrap();
            let json: Value = serde_json::from_str(&*res_text)?;
            // println!("gamestats {}", json);
            let game_mode = json["gameMode"].as_str();
            let is_aram = match game_mode {
                Some(mode) => {
                    mode.eq("ARAM")
                }
                None => {
                    false
                }
            };
            Ok(is_aram)
        }
        Err(_error) => {
            // println!("Not in game.");
            Ok(false)
        }
    }
}

fn handle_active_game(state: Value, summoner_name: &str) {
    let champions = state.as_array().unwrap();
    for champion in champions {
        if champion["summonerName"].as_str().unwrap().eq(summoner_name) {
            let is_dead = champion["isDead"].as_bool().unwrap();
            let respawn_timer = champion["respawnTimer"].as_f64().unwrap();
            if is_dead {
                print!("{}", "Death detected! Sending reminder in ".red().italic());
                println!("{} {}", respawn_timer.ceil().to_string().red(), "seconds...".red().italic());
                std::thread::sleep(std::time::Duration::from_secs(respawn_timer.ceil() as u64));
                println!("{}", "Friendly reminder to use the portal! :)".cyan().bold());
            }
        }
    }
}

async fn get_current_summoner(credentials: &Credentials) -> Result<String> {
    let url = format!("https://127.0.0.1:{}/lol-summoner/v1/current-summoner", credentials.port);
    let res = request_client_api(credentials, &*url).await
        .unwrap()
        .text().await
        .unwrap();
    let json: Value = serde_json::from_str(&*res)?;
    let summoner_name = json["displayName"].as_str().expect("summoner name string");
    Ok(summoner_name.to_owned())
}

async fn request_client_api(credentials: &Credentials, url: &str) -> std::result::Result<Response, Error> {
    return reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap()
        .get(url)
        .basic_auth("riot", Some(&credentials.password))
        .send().await;
}

fn get_password() -> Credentials {
    let command = "Get-CimInstance -Query \"SELECT * from Win32_Process WHERE name LIKE 'LeagueClientUx.exe'\" | Select-Object CommandLine | fl";
    let output = Command::new("powershell")
        .arg(command)
        .output()
        .expect("Cannot query League Client API");
    let output_str = String::from_utf8(output.stdout).unwrap();
    let password_regex = Regex::new(r"--remoting-auth-token=([\w_-]+)").unwrap();
    let password_captures = password_regex.captures(&*output_str).unwrap();
    let password = password_captures.get(1).map_or("", |m| m.as_str());

    let port_regex = Regex::new(r"--app-port=([0-9]+)").unwrap();
    let port_captures = port_regex.captures(&*output_str).unwrap();
    let port = port_captures.get(1).map_or("", |m| m.as_str());
    return Credentials {
        password: String::from(password),
        port: String::from(port)
    };
}

struct Credentials {
    password: String,
    port: String
}