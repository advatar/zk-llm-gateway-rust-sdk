use zk_llm_gateway_sdk::integration::AppGatewayConfig;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let prompt = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Explain how token classes reduce size leakage.".to_string());

    let system_prompt = std::env::var("SYSTEM_PROMPT")
        .unwrap_or_else(|_| "You are a helpful assistant.".to_string());

    let gateway = AppGatewayConfig::from_env()?.build().await?;
    let answer = gateway.ask_with_system(system_prompt, prompt).await?;

    println!("{answer}");
    Ok(())
}
