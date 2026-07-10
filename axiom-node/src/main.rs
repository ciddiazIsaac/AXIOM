fn main() {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create Tokio runtime");
    rt.block_on(async {
        if let Err(e) = axiom_node::run_server().await {
            eprintln!("Error fatal en axiom-node: {}", e);
            std::process::exit(1);
        }
    });
}
