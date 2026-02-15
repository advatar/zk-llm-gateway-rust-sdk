use zk_llm_gateway_sdk::{
    openai::{ChatCompletionsRequest, ChatMessage},
    ticket::FileTicketSource,
    GatewayClient, GatewayPublicKey, TokenClass,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let endpoint = std::env::var("GATEWAY_URL")?;
    let pk_b64 = std::env::var("GATEWAY_PUBLIC_KEY_B64")?;
    let tickets_path = std::env::var("TICKETS_JSON")?;

    let gateway_pk = GatewayPublicKey::from_base64(&pk_b64)?;
    let tickets = FileTicketSource::from_path(tickets_path).await?;

    let client = GatewayClient::new(endpoint.parse()?, gateway_pk, tickets);

    let req = ChatCompletionsRequest {
        model: std::env::var("MODEL").unwrap_or_else(|_| "gpt-4o-mini".to_string()),
        messages: vec![
            ChatMessage::system("You are a helpful assistant."),
            ChatMessage::user("Summarize the goal of ZK usage credits in one sentence."),
        ],
        temperature: Some(0.2),
        max_tokens: None,
        stream: Some(false),
        extra: Default::default(),
    };

    let resp = client.chat_completions(TokenClass::C2048, req).await?;
    println!("{}", resp.first_text().unwrap_or_default());

    Ok(())
}
