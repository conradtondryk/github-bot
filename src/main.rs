use std::env;
use teloxide::{prelude::*, types::{ChatId, ParseMode}};

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();

    let token = env::var("TELEGRAM_TOKEN").expect("TELEGRAM_TOKEN not set");
    let chat_id = env::var("TELEGRAM_CHAT_ID").expect("TELEGRAM_CHAT_ID not set")
        .parse::<i64>().expect("Invalid chat ID");

    let bot = Bot::new(token);

    if let Err(e) = bot.send_message(ChatId(chat_id), "Hello from Rust\\! 🦀")
        .parse_mode(ParseMode::MarkdownV2)
        .await
    {
        eprintln!("Failed to send message: {}", e);
    } else {
        println!("Message sent successfully!");
    }
}
