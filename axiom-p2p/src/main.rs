use clap::Parser;
use libp2p::{identity::Keypair, Multiaddr, PeerId};
use tokio::io::{stdin, AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use std::time::Duration;
use std::env;
use axiom_p2p::node::{NodeConfig, ValidatorNode};

#[derive(Parser, Debug)]
#[command(author, version, about = "AXIOM Validator Node — P2P revocation network")]
struct Args {
    /// Puerto TCP para escuchar (0 para aleatorio)
    #[arg(short, long, default_value_t = 0)]
    port: u16,

    /// Multiaddr de un nodo bootstrap al que conectarse (opcional)
    #[arg(short, long)]
    bootstrap: Option<String>,

    /// Nombre legible del nodo (solo para logs)
    #[arg(short, long, default_value = "validator")]
    name: String,

    /// Publica una revocación automáticamente después de N segundos (para testing).
    /// Formato: <credential_id> o <credential_id>:<delay_secs>
    /// Ejemplo: --auto-revoke cred-test-123 (default 5s)
    /// Ejemplo: --auto-revoke cred-test-123:10
    #[arg(long)]
    auto_revoke: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    
    let args = Args::parse();

    // Cargar variables de entorno desde .env (opcional)
    dotenvy::dotenv().ok();

    // 1. Generar o cargar la identidad del nodo (clave ed25519)
    let local_key = if let Ok(hex_key) = env::var("AXIOM_P2P_SECRET_KEY") {
        let mut bytes = hex::decode(hex_key).expect("AXIOM_P2P_SECRET_KEY debe ser un string hexadecimal válido de 64 caracteres");
        libp2p::identity::Keypair::ed25519_from_bytes(&mut bytes).expect("Clave ed25519 inválida en AXIOM_P2P_SECRET_KEY")
    } else {
        let key = Keypair::generate_ed25519();
        if let Ok(ed_key) = key.clone().try_into_ed25519() {
            let secret_key = ed_key.secret();
            let secret = secret_key.as_ref();
            tracing::warn!("============================================================");
            tracing::warn!("⚠️  ADVERTENCIA: No se encontró AXIOM_P2P_SECRET_KEY en .env");
            tracing::warn!("Se ha generado una identidad EFÍMERA para este arranque.");
            tracing::warn!("Para hacerla persistente, añade esto a tu archivo .env:");
            tracing::warn!("AXIOM_P2P_SECRET_KEY={}", hex::encode(secret));
            tracing::warn!("============================================================");
        }
        key
    };

    let local_peer_id = PeerId::from(local_key.public());
    tracing::info!("=== AXIOM Validator Node [{}] ===", args.name);
    tracing::info!("Peer ID: {}", local_peer_id);

    // 2. Parsear dirección de escucha
    let listen_addr: Multiaddr = format!("/ip4/0.0.0.0/tcp/{}", args.port).parse()?;

    // 3. Parsear nodos bootstrap si se proveen
    let mut bootstrap_nodes = Vec::new();
    if let Some(b) = args.bootstrap {
        let addr: Multiaddr = b.parse()?;

        // Extraer el PeerId de la Multiaddr (esperamos que termine en /p2p/<peer_id>)
        let mut peer_id = None;
        for protocol in addr.iter() {
            if let libp2p::multiaddr::Protocol::P2p(p) = protocol {
                peer_id = Some(p);
            }
        }

        if let Some(pid) = peer_id {
            bootstrap_nodes.push((pid, addr));
            tracing::info!("[{}] Usando nodo bootstrap: {}", args.name, pid);
        } else {
            tracing::warn!("Advertencia: La dirección bootstrap no contiene un /p2p/<peer_id>. Ignorando.");
        }
    }

    // 4. Configurar y construir el nodo
    let config = NodeConfig {
        local_key,
        listen_addr,
        bootstrap_nodes,
        dial_addrs: vec![],
        storage_path: None,
    };

    let node = ValidatorNode::new(config)?;

    // 5. Canal para enviar comandos desde stdin al nodo
    let (tx, rx) = mpsc::channel(100);

    // 6. Si hay --auto-revoke, programar el envío automático
    if let Some(auto_revoke_spec) = args.auto_revoke {
        let tx_auto = tx.clone();
        let name = args.name.clone();

        // Parsear "cred-id" o "cred-id:delay_secs"
        let (cred_id, delay_secs) = if let Some((id, delay_str)) = auto_revoke_spec.split_once(':') {
            let secs: u64 = delay_str.parse().unwrap_or(5);
            (id.to_string(), secs)
        } else {
            (auto_revoke_spec, 5u64)
        };

        tracing::info!("[{}] Auto-revoke programado: '{}' en {}s", name, cred_id, delay_secs);

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(delay_secs)).await;
            tracing::info!("[{}] Ejecutando auto-revoke de '{}'...", name, cred_id);
            let cmd = format!("revoke {}", cred_id);
            if tx_auto.send(cmd).await.is_err() {
                tracing::error!("[{}] Error: canal de comandos cerrado", name);
            }
        });
    }

    // 7. Tarea para leer de stdin
    tokio::spawn(async move {
        let stdin = stdin();
        let mut reader = BufReader::new(stdin);
        let mut line = String::new();
        loop {
            line.clear();
            if let Ok(bytes) = reader.read_line(&mut line).await {
                if bytes == 0 {
                    break;
                }
                let _ = tx.send(line.clone()).await;
            }
        }
    });

    tracing::info!("\nComandos disponibles:");
    tracing::info!("  revoke <id>   - Revocar la credencial con el ID dado");
    tracing::info!("  status        - Ver el estado del CRDT");
    tracing::info!("------------------------------------------------------\n");

    // 8. Arrancar el Swarm en bucle eterno
    tracing::info!("Iniciando nodo validador...");
    node.run(rx).await;

    Ok(())
}
