//! Test E2E: Dos nodos en local, uno publica una revocación, el otro la recibe.
//!
//! Este test valida el flujo completo de Paso 6:
//! 1. Arranca Nodo A y Nodo B en puertos TCP locales
//! 2. Espera a que mDNS los descubra mutuamente
//! 3. Nodo A publica una revocación via NodeCommand::Revoke
//! 4. Verifica que Nodo B actualiza su CRDT con la revocación
//!
//! No usa bootstrap externo — los nodos se descubren por mDNS en localhost.

use axiom_p2p::node::{NodeConfig, NodeCommand};
use axiom_p2p::ValidatorNode;
use libp2p::identity::Keypair;
use libp2p::Multiaddr;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep, Duration, timeout};


/// Helper mejorado: crea y arranca un nodo, devuelve solo el sender + peer_id.
fn spawn_node_bg(port: u16, dial: Option<Multiaddr>) -> (mpsc::Sender<NodeCommand>, libp2p::PeerId) {
    let key = Keypair::generate_ed25519();
    let peer_id = libp2p::PeerId::from(key.public());
    let listen_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{}", port).parse().unwrap();

    let dial_addrs = if let Some(d) = dial { vec![d] } else { vec![] };

    let config = NodeConfig {
        local_key: key,
        listen_addr,
        bootstrap_nodes: vec![],
        dial_addrs,
        storage_path: None,
    };

    let node = ValidatorNode::new(config).expect("fallo al crear nodo");
    let (tx, rx) = mpsc::channel(100);

    tokio::spawn(async move {
        node.run_with_commands(rx).await;
    });

    (tx, peer_id)
}

/// Helper: consulta el count del CRDT de un nodo vía su canal de comandos.
async fn query_count(tx: &mpsc::Sender<NodeCommand>) -> usize {
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(NodeCommand::QueryCount { response: resp_tx }).await.unwrap();
    resp_rx.await.unwrap()
}

/// Helper: consulta si una credencial está revocada en un nodo.
async fn query_is_revoked(tx: &mpsc::Sender<NodeCommand>, cred_id: &str) -> bool {
    let (resp_tx, resp_rx) = oneshot::channel();
    tx.send(NodeCommand::IsRevoked {
        credential_id: cred_id.to_string(),
        response: resp_tx,
    }).await.unwrap();
    resp_rx.await.unwrap()
}

/// Test principal: Nodo A revoca, Nodo B la recibe por Gossipsub + mDNS.
///
/// Usa puertos fijos 19100/19101 para evitar conflictos con otros tests.
/// El timeout total es de 60 segundos — mDNS puede tardar unos segundos
/// en descubrir pares en la misma máquina.
#[tokio::test]
async fn test_two_nodes_revocation_propagation() {
    println!("\n========================================");
    println!("  E2E TEST: Propagación de Revocación");
    println!("========================================\n");

    // 1. Arrancar dos nodos, B marca explícitamente a A como dial_addr para evitar depender de mDNS
    let addr_a: Multiaddr = "/ip4/127.0.0.1/tcp/19100".parse().unwrap();
    let (tx_a, peer_a) = spawn_node_bg(19100, None);
    let (tx_b, peer_b) = spawn_node_bg(19101, Some(addr_a));

    println!("[Test] Nodo A: {}", peer_a);
    println!("[Test] Nodo B: {}", peer_b);

    // 2. Esperar a que mDNS los descubra (puede tardar 5-15 segundos)
    println!("[Test] Esperando descubrimiento mDNS...");
    sleep(Duration::from_secs(10)).await;

    // 3. Verificar que ambos nodos empiezan vacíos
    let count_a = query_count(&tx_a).await;
    let count_b = query_count(&tx_b).await;
    println!("[Test] Estado inicial — Nodo A: {} revocaciones, Nodo B: {} revocaciones", count_a, count_b);
    assert_eq!(count_a, 0, "Nodo A debería empezar sin revocaciones");
    assert_eq!(count_b, 0, "Nodo B debería empezar sin revocaciones");

    // 4. Nodo A publica una revocación
    let cred_id = "cred-e2e-test-001";
    println!("[Test] Nodo A revocando '{}'...", cred_id);
    tx_a.send(NodeCommand::Revoke {
        credential_id: cred_id.to_string(),
        issuer_did: "did:axiom:e2e-test-issuer".to_string(),
        reason: "e2e test revocation".to_string(),
    }).await.unwrap();

    // 5. Verificar que Nodo A tiene la revocación localmente
    sleep(Duration::from_millis(500)).await;
    let is_revoked_a = query_is_revoked(&tx_a, cred_id).await;
    assert!(is_revoked_a, "Nodo A debería tener la revocación localmente");
    println!("[Test] ✓ Nodo A tiene la revocación localmente");

    // 6. Esperar a que Gossipsub propague la revocación a Nodo B
    //    Gossipsub heartbeat es cada 10s, así que esperamos hasta 30s con polling.
    println!("[Test] Esperando propagación Gossipsub a Nodo B...");
    let propagated = timeout(Duration::from_secs(45), async {
        loop {
            if query_is_revoked(&tx_b, cred_id).await {
                return true;
            }
            sleep(Duration::from_secs(2)).await;
        }
    }).await;

    match propagated {
        Ok(true) => {
            let count_b = query_count(&tx_b).await;
            println!("[Test] ✓ Nodo B recibió la revocación. Total: {}", count_b);
            println!("\n========================================");
            println!("  ✅ E2E TEST PASSED");
            println!("========================================\n");
        }
        _ => {
            let count_b = query_count(&tx_b).await;
            panic!(
                "❌ FALLÓ: Nodo B no recibió la revocación después de 45s. \
                 Count en Nodo B: {}. \
                 Esto puede significar que mDNS no descubrió los pares \
                 o Gossipsub no propagó el mensaje.",
                count_b
            );
        }
    }
}

/// Test: Múltiples revocaciones convergen en ambos nodos.
#[tokio::test]
async fn test_multiple_revocations_converge() {
    println!("\n========================================");
    println!("  E2E TEST: Convergencia Múltiple");
    println!("========================================\n");

    let addr_a: Multiaddr = "/ip4/127.0.0.1/tcp/19200".parse().unwrap();
    let (tx_a, _) = spawn_node_bg(19200, None);
    let (tx_b, _) = spawn_node_bg(19201, Some(addr_a.clone()));
    let (tx_c, _) = spawn_node_bg(19202, Some(addr_a));

    // Esperar descubrimiento mDNS
    sleep(Duration::from_secs(10)).await;

    // Nodo A revoca 3 credenciales
    for i in 1..=3 {
        let cred = format!("cred-multi-{}", i);
        tx_a.send(NodeCommand::Revoke {
            credential_id: cred,
            issuer_did: "did:axiom:multi-test".to_string(),
            reason: "batch test".to_string(),
        }).await.unwrap();
        sleep(Duration::from_millis(200)).await;
    }

    // Esperar propagación
    let all_propagated = timeout(Duration::from_secs(45), async {
        loop {
            let count = query_count(&tx_b).await;
            if count >= 3 {
                return true;
            }
            sleep(Duration::from_secs(2)).await;
        }
    }).await;

    assert!(
        all_propagated.is_ok(),
        "No todas las revocaciones llegaron a Nodo B en 45s"
    );

    // Verificar cada una
    for i in 1..=3 {
        let cred = format!("cred-multi-{}", i);
        assert!(
            query_is_revoked(&tx_b, &cred).await,
            "Nodo B debería tener '{}'",
            cred
        );
    }

    println!("[Test] ✓ Las 3 revocaciones convergieron en Nodo B");
    println!("\n========================================");
    println!("  ✅ E2E TEST PASSED");
    println!("========================================\n");
}
