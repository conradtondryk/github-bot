use anyhow::{Context, Result};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::{env, sync::Arc};
use teloxide::{prelude::*, types::{ChatId, ParseMode}};
use tracing::{info, error};

type HmacSha256 = Hmac<Sha256>;

const DEFAULT_PORT: &str = "3000";

#[derive(Clone)]
struct AppState {
    bot: Bot,
    chat_id: ChatId,
    webhook_secret: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubPushEvent {
    #[serde(rename = "ref")]
    git_ref: String,
    repository: Repository,
    pusher: Pusher,
    commits: Vec<Commit>,
    compare: String,
}

#[derive(Debug, Deserialize)]
struct Repository {
    full_name: String,
}

#[derive(Debug, Deserialize)]
struct Pusher {
    name: String,
}

#[derive(Debug, Deserialize)]
struct Commit {
    id: String,
    message: String,
    author: Author,
}

#[derive(Debug, Deserialize)]
struct Author {
    name: String,
    username: Option<String>,
}

fn verify_signature(secret: &str, signature: &str, payload: &[u8]) -> bool {
    signature
        .strip_prefix("sha256=")
        .and_then(|hex| hex::decode(hex).ok())
        .filter(|bytes| !bytes.is_empty())
        .map(|sig_bytes| {
            HmacSha256::new_from_slice(secret.as_bytes())
                .expect("HMAC can take key of any size")
                .chain_update(payload)
                .verify_slice(&sig_bytes)
                .is_ok()
        })
        .unwrap_or(false)
}

fn format_telegram_message(event: &GitHubPushEvent) -> String {
    let branch = event.git_ref.strip_prefix("refs/heads/").unwrap_or(&event.git_ref);
    let commits_word = if event.commits.len() == 1 { "commit" } else { "commits" };

    let mut message = format!(
        "🔔 *New Push to {}*\n\n\
         👤 *Pusher:* {}\n\
         🌿 *Branch:* `{}`\n\
         📝 *{} {}*\n\n",
        escape_markdown(&event.repository.full_name),
        escape_markdown(&event.pusher.name),
        escape_markdown(branch),
        event.commits.len(),
        commits_word
    );

    for commit in event.commits.iter().take(5) {
        let short_sha = &commit.id[..7];
        let first_line = commit.message.lines().next().unwrap_or("");
        let author = commit.author.username.as_ref().unwrap_or(&commit.author.name);

        message.push_str(&format!(
            "• `{}` {} \\- _{}_\n",
            escape_markdown(short_sha),
            escape_markdown(first_line),
            escape_markdown(author)
        ));
    }

    if event.commits.len() > 5 {
        message.push_str(&format!("\n_\\.\\.\\. and {} more commits_\n", event.commits.len() - 5));
    }

    message.push_str(&format!("\n[View Changes]({})", escape_markdown(&event.compare)));
    message
}

const MARKDOWN_SPECIAL_CHARS: &[char] = &['_', '*', '[', ']', '(', ')', '~', '`', '>', '#', '+', '-', '=', '|', '{', '}', '.', '!'];

fn escape_markdown(text: &str) -> String {
    text.chars()
        .flat_map(|c| if MARKDOWN_SPECIAL_CHARS.contains(&c) {
            vec!['\\', c]
        } else {
            vec![c]
        })
        .collect()
}

async fn webhook_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("Received webhook request");

    if let Some(secret) = &state.webhook_secret {
        let signature = headers
            .get("x-hub-signature-256")
            .and_then(|h| h.to_str().ok())
            .ok_or_else(|| {
                error!("Missing webhook signature");
                (StatusCode::UNAUTHORIZED, "Missing signature".to_string())
            })?;

        if !verify_signature(secret, signature, &body) {
            error!("Invalid webhook signature");
            return Err((StatusCode::UNAUTHORIZED, "Invalid signature".to_string()));
        }
    }

    let event = serde_json::from_slice::<GitHubPushEvent>(&body).map_err(|e| {
        error!("Failed to parse payload: {}", e);
        (StatusCode::BAD_REQUEST, format!("Invalid payload: {}", e))
    })?;

    info!("Push event: {} commits to {}", event.commits.len(), event.repository.full_name);

    state.bot
        .send_message(state.chat_id, format_telegram_message(&event))
        .parse_mode(ParseMode::MarkdownV2)
        .await
        .map_err(|e| {
            error!("Failed to send Telegram message: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send notification".to_string())
        })?;

    info!("Successfully sent notification to Telegram");
    Ok((StatusCode::OK, "Notification sent"))
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv().ok();

    let token = env::var("TELEGRAM_TOKEN").context("TELEGRAM_TOKEN not set")?;
    let chat_id = env::var("TELEGRAM_CHAT_ID")
        .context("TELEGRAM_CHAT_ID not set")?
        .parse::<i64>()
        .context("Invalid TELEGRAM_CHAT_ID format")?;
    let webhook_secret = env::var("GITHUB_WEBHOOK_SECRET").ok().filter(|s| !s.is_empty());
    let port = env::var("PORT")
        .as_deref()
        .unwrap_or(DEFAULT_PORT)
        .parse::<u16>()
        .context("Invalid PORT format")?;

    let state = Arc::new(AppState {
        bot: Bot::new(token),
        chat_id: ChatId(chat_id),
        webhook_secret,
    });

    let app = Router::new()
        .route("/webhook", post(webhook_handler))
        .route("/health", axum::routing::get(health_check))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("Failed to bind to address")?;

    info!("🚀 GitHub bot is running on http://{}", addr);
    info!("Webhook endpoint: http://{}/webhook", addr);

    axum::serve(listener, app)
        .await
        .context("Server failed to start")?;

    Ok(())
}
