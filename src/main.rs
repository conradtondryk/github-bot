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
    name: String,
    full_name: String,
    html_url: String,
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
    url: String,
}

#[derive(Debug, Deserialize)]
struct Author {
    name: String,
    username: Option<String>,
}

fn verify_signature(secret: &str, signature: &str, payload: &[u8]) -> bool {
    // GitHub sends signature as "sha256=<hex>"
    let sig_bytes = match signature.strip_prefix("sha256=") {
        Some(hex) => match hex::decode(hex) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        },
        None => return false,
    };

    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .expect("HMAC can take key of any size");
    mac.update(payload);

    mac.verify_slice(&sig_bytes).is_ok()
}

fn format_telegram_message(event: &GitHubPushEvent) -> String {
    let branch = event.git_ref.strip_prefix("refs/heads/").unwrap_or(&event.git_ref);
    let commit_count = event.commits.len();
    let commits_word = if commit_count == 1 { "commit" } else { "commits" };

    let mut message = format!(
        "🔔 *New Push to {}*\n\n",
        escape_markdown(&event.repository.full_name)
    );

    message.push_str(&format!(
        "👤 *Pusher:* {}\n",
        escape_markdown(&event.pusher.name)
    ));

    message.push_str(&format!(
        "🌿 *Branch:* `{}`\n",
        escape_markdown(branch)
    ));

    message.push_str(&format!(
        "📝 *{} {}*\n\n",
        commit_count,
        commits_word
    ));

    // Show up to 5 commits
    for commit in event.commits.iter().take(5) {
        let short_sha = &commit.id[..7];
        let first_line = commit.message.lines().next().unwrap_or("");
        let author = commit.author.username.as_ref()
            .unwrap_or(&commit.author.name);

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

    message.push_str(&format!(
        "\n[View Changes]({})",
        escape_markdown(&event.compare)
    ));

    message
}

fn escape_markdown(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '_' | '*' | '[' | ']' | '(' | ')' | '~' | '`' | '>' | '#' | '+' | '-' | '=' | '|' | '{' | '}' | '.' | '!' => {
                format!("\\{}", c)
            }
            _ => c.to_string(),
        })
        .collect()
}

async fn webhook_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    info!("Received webhook request");

    // Verify GitHub signature if secret is configured
    if let Some(secret) = &state.webhook_secret {
        if let Some(signature) = headers.get("x-hub-signature-256") {
            let sig_str = signature.to_str().unwrap_or("");
            if !verify_signature(secret, sig_str, &body) {
                error!("Invalid webhook signature");
                return (StatusCode::UNAUTHORIZED, "Invalid signature").into_response();
            }
        } else {
            error!("Missing webhook signature");
            return (StatusCode::UNAUTHORIZED, "Missing signature").into_response();
        }
    }

    // Parse the payload
    let event: GitHubPushEvent = match serde_json::from_slice(&body) {
        Ok(e) => e,
        Err(e) => {
            error!("Failed to parse payload: {}", e);
            return (StatusCode::BAD_REQUEST, format!("Invalid payload: {}", e)).into_response();
        }
    };

    info!("Push event: {} commits to {}", event.commits.len(), event.repository.full_name);

    // Format and send message
    let message = format_telegram_message(&event);

    match state.bot
        .send_message(state.chat_id, message)
        .parse_mode(ParseMode::MarkdownV2)
        .await
    {
        Ok(_) => {
            info!("Successfully sent notification to Telegram");
            (StatusCode::OK, "Notification sent").into_response()
        }
        Err(e) => {
            error!("Failed to send Telegram message: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to send notification").into_response()
        }
    }
}

async fn health_check() -> impl IntoResponse {
    (StatusCode::OK, "OK")
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    // Load environment variables
    dotenvy::dotenv().ok();

    let token = env::var("TELEGRAM_TOKEN").expect("TELEGRAM_TOKEN not set");
    let chat_id = env::var("TELEGRAM_CHAT_ID")
        .expect("TELEGRAM_CHAT_ID not set")
        .parse::<i64>()
        .expect("Invalid chat ID");
    let webhook_secret = env::var("GITHUB_WEBHOOK_SECRET")
        .ok()
        .filter(|s| !s.is_empty());
    let port = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .expect("Invalid PORT");

    let bot = Bot::new(token);

    let state = Arc::new(AppState {
        bot,
        chat_id: ChatId(chat_id),
        webhook_secret,
    });

    // Build the router
    let app = Router::new()
        .route("/webhook", post(webhook_handler))
        .route("/health", axum::routing::get(health_check))
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    info!("Starting server on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("Failed to bind to address");

    info!("🚀 GitHub bot is running on http://{}", addr);
    info!("Webhook endpoint: http://{}/webhook", addr);

    axum::serve(listener, app)
        .await
        .expect("Server failed to start");
}
