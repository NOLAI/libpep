pub(crate) fn get_ina() -> Option<f64> {
    let url = std::env::var("ENERGY_STATS").ok()?;
    let agent: ureq::Agent = ureq::AgentBuilder::new()
        .user_agent(&format!(
            "{} {}/{}",
            env!("CARGO_PKG_NAME"),
            buildinfy::build_reference().unwrap_or_default(),
            buildinfy::build_pipeline_id_per_project().unwrap_or_default()
        ))
        .timeout_read(std::time::Duration::from_secs(60))
        .timeout_write(std::time::Duration::from_secs(5))
        .build();
    let resp = agent.get(&url).call().ok()?;
    resp.header("X-Electricity-Consumed-Total")?.parse().ok()
}
