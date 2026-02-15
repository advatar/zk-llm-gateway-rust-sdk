#[cfg(feature = "redaction")]
fn main() {
    use zk_llm_gateway_sdk::redaction::{RedactionMode, Redactor};

    let mut redactor = Redactor::new(RedactionMode::StablePerValue);
    redactor.add_custom_term("ACME_INTERNAL_PROJECT");

    let input = "Email me at alice@example.com. My ETH is 0x0123456789aBCDEF0123456789abcdef01234567. sk-verysecretapikey";
    let res = redactor.redact_text(input);

    println!("Original: {input}");
    println!("Redacted: {}", res.redacted);

    let restored = redactor.rehydrate_text(&res.redacted, &res.map);
    println!("Restored: {restored}");
}

#[cfg(not(feature = "redaction"))]
fn main() {
    eprintln!("Enable the 'redaction' feature to run this example.");
}
