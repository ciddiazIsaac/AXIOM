use libp2p::{
    gossipsub, identify, kad, mdns, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
    identity::Keypair, swarm::SwarmEvent,
};
use futures::StreamExt;
use std::error::Error;
use std::time::Duration;
use tokio::time;
use tokio::select;
use tokio::sync::oneshot;

use crate::behaviour::{ValidatorBehaviour, ValidatorBehaviourEvent};
use crate::crdt::RevocationCrdt;
use crate::message::{GossipPayload, RevocationMessage};

/// Comandos programáticos para controlar el nodo.
///
/// Permite enviar revocaciones y queries desde código (tests, API)
/// sin depender de stdin.
pub enum NodeCommand {
    /// Publica una revocación en la red.
    Revoke {
        credential_id: String,
        issuer_did: String,
        reason: String,
    },
    /// Consulta cuántas revocaciones tiene el CRDT.
    QueryCount {
        response: oneshot::Sender<usize>,
    },
    /// Consulta si una credencial está revocada.
    IsRevoked {
        credential_id: String,
        response: oneshot::Sender<bool>,
    },
    /// Obtiene la dirección de escucha actual del nodo.
    GetListenAddr {
        response: oneshot::Sender<Option<Multiaddr>>,
    },
}

pub struct NodeConfig {
    pub local_key: Keypair,
    pub listen_addr: Multiaddr,
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    pub dial_addrs: Vec<Multiaddr>,
    pub storage_path: Option<String>,
}

pub struct ValidatorNode {
    swarm: Swarm<ValidatorBehaviour>,
    bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
    dial_addrs: Vec<Multiaddr>,
    crdt: RevocationCrdt,
    /// Flag: si acabamos de unirnos a la red y necesitamos pedir el estado completo.
    needs_sync: bool,
}

impl ValidatorNode {
    pub fn new(config: NodeConfig) -> Result<Self, Box<dyn Error>> {
        let swarm = SwarmBuilder::with_existing_identity(config.local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|key| ValidatorBehaviour::new(key).unwrap())?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let crdt = match &config.storage_path {
            Some(path) => RevocationCrdt::with_storage(path)?,
            None => RevocationCrdt::new(),
        };

        let mut node = Self {
            swarm,
            bootstrap_nodes: config.bootstrap_nodes,
            dial_addrs: config.dial_addrs,
            crdt,
            needs_sync: true, // Al arrancar, necesitamos sync
        };

        // Flush del estado inicial del documento Automerge para que
        // los deltas posteriores solo contengan cambios reales.
        let _ = node.crdt.save_incremental();

        // Escuchar en la dirección configurada
        node.swarm.listen_on(config.listen_addr)?;

        Ok(node)
    }

    /// Ejecuta el nodo con comandos de texto (desde stdin).
    /// Convierte cada línea en un `NodeCommand` internamente.
    pub async fn run(self, mut string_rx: tokio::sync::mpsc::Receiver<String>) {
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::channel(100);

        // Tarea que convierte strings a NodeCommand
        tokio::spawn(async move {
            while let Some(line) = string_rx.recv().await {
                let cmd = line.trim().to_string();
                if cmd.starts_with("revoke ") {
                    let parts: Vec<&str> = cmd.split_whitespace().collect();
                    if parts.len() == 2 {
                        let _ = cmd_tx.send(NodeCommand::Revoke {
                            credential_id: parts[1].to_string(),
                            issuer_did: "did:axiom:local".to_string(),
                            reason: "manual revocation".to_string(),
                        }).await;
                    } else {
                        println!("[Validator] Uso: revoke <credential_id>");
                    }
                } else if cmd == "status" {
                    let (tx, rx) = oneshot::channel();
                    let _ = cmd_tx.send(NodeCommand::QueryCount { response: tx }).await;
                    if let Ok(count) = rx.await {
                        println!("[Validator] Revocaciones totales en CRDT: {}", count);
                    }
                } else if !cmd.is_empty() {
                    println!("[Validator] Comando desconocido. Usa 'revoke <credential_id>' o 'status'");
                }
            }
        });

        self.run_with_commands(cmd_rx).await;
    }

    /// Ejecuta el nodo con comandos programáticos tipados.
    /// Usado directamente por tests de integración.
    pub async fn run_with_commands(mut self, mut command_rx: tokio::sync::mpsc::Receiver<NodeCommand>) {
        // Temporizador para comprobar la conexión con otros pares cada 30 segundos
        let mut no_peer_interval = time::interval(Duration::from_secs(30));
        no_peer_interval.tick().await; // Consumir el primer tick inmediato

        let mut discovered_any = false;

        // Intentar arranque inicial si hay nodos bootstrap o direcciones a marcar
        if !self.bootstrap_nodes.is_empty() || !self.dial_addrs.is_empty() {
            self.attempt_bootstrap();
        }

        loop {
            select! {
                Some(cmd) = command_rx.recv() => {
                    self.handle_command(cmd).await;
                }
                // Cada 30 segundos verificamos si hemos encontrado pares
                _ = no_peer_interval.tick() => {
                    if !discovered_any {
                        println!("[Validator] No se descubrieron pares en los últimos 30s. Reintentando bootstrap...");
                        self.attempt_bootstrap();
                    } else {
                        // Reiniciamos el flag para el siguiente intervalo si es que queremos 
                        // seguir verificando la conectividad continuamente.
                        discovered_any = false;
                    }
                }

                // Procesamos eventos del Swarm
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            println!("[Validator] Escuchando en {:?}", address);
                        }
                        
                        // Eventos mDNS (Descubrimiento Local)
                        SwarmEvent::Behaviour(ValidatorBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (peer_id, multiaddr) in list {
                                println!("[Validator] mDNS descubrió al par: {}", peer_id);
                                // Añadimos la dirección a la DHT de Kademlia
                                self.swarm.behaviour_mut().kad.add_address(&peer_id, multiaddr);
                                // Añadimos como par explícito de Gossipsub para que
                                // pueda publicar sin esperar a la formación del mesh.
                                self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                                discovered_any = true;
                            }
                            // Si acabamos de descubrir pares y necesitamos sync, pedirlo
                            if self.needs_sync && discovered_any {
                                self.request_full_sync();
                            }
                        }
                        SwarmEvent::Behaviour(ValidatorBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (peer_id, _multiaddr) in list {
                                println!("[Validator] mDNS expiró al par: {}", peer_id);
                            }
                        }

                        // Eventos Identify (Intercambio de info)
                        SwarmEvent::Behaviour(ValidatorBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            println!("[Validator] Identify recibido del par: {}", peer_id);
                            for addr in info.listen_addrs {
                                // Almacenamos la info de enrutamiento en Kademlia
                                self.swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                            }
                            // Asegurar que Gossipsub puede comunicarse con este par
                            self.swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            discovered_any = true;

                            // Si acabamos de identificar pares y necesitamos sync, pedirlo
                            if self.needs_sync {
                                self.request_full_sync();
                            }
                        }

                        // Eventos Kademlia (Descubrimiento Global / DHT)
                        SwarmEvent::Behaviour(ValidatorBehaviourEvent::Kad(kad::Event::OutboundQueryProgressed { result, .. })) => {
                            match result {
                                kad::QueryResult::Bootstrap(Ok(_)) => {
                                    println!("[Validator] Kademlia bootstrap exitoso");
                                    discovered_any = true;
                                }
                                kad::QueryResult::Bootstrap(Err(e)) => {
                                    println!("[Validator] Kademlia bootstrap falló: {:?}", e);
                                }
                                _ => {}
                            }
                        }
                        
                        // ═══════════════════════════════════════════════════
                        // Eventos Gossipsub — Integración con Automerge CRDT
                        // ═══════════════════════════════════════════════════
                        SwarmEvent::Behaviour(ValidatorBehaviourEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                            self.handle_gossipsub_message(&message.data).await;
                        }
                        
                        _ => {}
                    }
                }
            }
        }
    }

    /// Procesa un `NodeCommand` tipado.
    async fn handle_command(&mut self, cmd: NodeCommand) {
        match cmd {
            NodeCommand::Revoke { credential_id, issuer_did, reason } => {
                let revocation = RevocationMessage {
                    credential_id,
                    issuer_did,
                    timestamp: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs(),
                    reason,
                };
                if let Err(e) = self.publish_revocation(&revocation).await {
                    println!("[Validator] Error al publicar revocación: {:?}", e);
                }
            }
            NodeCommand::QueryCount { response } => {
                let _ = response.send(self.crdt.count());
            }
            NodeCommand::IsRevoked { credential_id, response } => {
                let _ = response.send(self.crdt.is_revoked(&credential_id));
            }
            NodeCommand::GetListenAddr { response } => {
                let addrs: Vec<_> = self.swarm.listeners().cloned().collect();
                let _ = response.send(addrs.into_iter().next());
            }
        }
    }

    /// Maneja un mensaje recibido por Gossipsub.
    ///
    /// Deserializa el `GossipPayload` y ejecuta la acción correspondiente:
    /// - `RevocationChange`: aplica el delta incremental de Automerge
    /// - `SyncRequest`: responde con el estado completo del CRDT
    /// - `SyncResponse`: fusiona el estado completo recibido
    async fn handle_gossipsub_message(&mut self, data: &[u8]) {
        match serde_json::from_slice::<GossipPayload>(data) {
            Ok(GossipPayload::RevocationChange(change_bytes)) => {
                println!("[Validator] Cambio incremental de Automerge recibido ({} bytes)", change_bytes.len());
                match self.crdt.apply_incremental(&change_bytes).await {
                    Ok(()) => {
                        println!(
                            "[Validator] CRDT actualizado. Total revocaciones: {}",
                            self.crdt.count()
                        );
                    }
                    Err(e) => {
                        println!("[Validator] Error al aplicar cambio incremental: {:?}", e);
                    }
                }
            }
            Ok(GossipPayload::SyncRequest) => {
                println!("[Validator] SyncRequest recibido. Enviando estado completo...");
                let full_state = self.crdt.save_full();
                let response = GossipPayload::SyncResponse(full_state);
                if let Err(e) = self.publish_payload(&response) {
                    println!("[Validator] Error al enviar SyncResponse: {:?}", e);
                }
            }
            Ok(GossipPayload::SyncResponse(full_bytes)) => {
                println!(
                    "[Validator] SyncResponse recibido ({} bytes). Fusionando...",
                    full_bytes.len()
                );
                match self.crdt.merge_full(&full_bytes).await {
                    Ok(()) => {
                        self.needs_sync = false;
                        println!(
                            "[Validator] Sync completo exitoso. Total revocaciones: {}",
                            self.crdt.count()
                        );
                    }
                    Err(e) => {
                        println!("[Validator] Error al fusionar estado completo: {:?}", e);
                    }
                }
            }
            Err(e) => {
                println!("[Validator] No se pudo deserializar GossipPayload: {:?}", e);
            }
        }
    }

    /// Publica una revocación en la red.
    ///
    /// 1. Inserta la revocación en el documento Automerge local
    /// 2. Genera el delta incremental
    /// 3. Lo envuelve en `GossipPayload::RevocationChange` y lo publica
    pub async fn publish_revocation(&mut self, revocation: &RevocationMessage) -> Result<(), Box<dyn Error>> {
        // Mutar el documento Automerge local
        let is_new = self.crdt.add(revocation).await;

        if is_new {
            println!(
                "[Validator] Credencial {} revocada localmente. Propagando delta...",
                revocation.credential_id
            );
        } else {
            println!(
                "[Validator] Credencial {} ya estaba revocada. Re-propagando por consistencia.",
                revocation.credential_id
            );
        }

        // Obtener el delta incremental (solo los cambios nuevos)
        let delta = self.crdt.save_incremental();
        let payload = GossipPayload::RevocationChange(delta);

        self.publish_payload(&payload)?;

        println!("[Validator] Revocación publicada en Gossipsub como delta Automerge.");
        Ok(())
    }

    /// Consulta si una credencial está revocada en el estado local del CRDT.
    pub fn is_revoked(&self, credential_id: &str) -> bool {
        self.crdt.is_revoked(credential_id)
    }

    /// Solicita el estado completo del CRDT a la red.
    /// Se usa cuando un nodo se une tarde y necesita sincronizarse.
    fn request_full_sync(&mut self) {
        println!("[Validator] Solicitando estado completo del CRDT a la red (SyncRequest)...");
        let payload = GossipPayload::SyncRequest;
        if let Err(e) = self.publish_payload(&payload) {
            println!("[Validator] Error al enviar SyncRequest: {:?}", e);
        }
    }

    /// Publica un `GossipPayload` serializado en el topic de revocaciones.
    fn publish_payload(&mut self, payload: &GossipPayload) -> Result<(), Box<dyn Error>> {
        let topic = gossipsub::IdentTopic::new("axiom/revocations/1.0.0");
        let data = serde_json::to_vec(payload)?;
        self.swarm.behaviour_mut().gossipsub.publish(topic, data)?;
        Ok(())
    }

    fn attempt_bootstrap(&mut self) {
        let mut added = false;
        for (peer, addr) in &self.bootstrap_nodes {
            println!("[Validator] Añadiendo nodo bootstrap {} en {}", peer, addr);
            self.swarm.behaviour_mut().kad.add_address(peer, addr.clone());
            added = true;
        }

        if added {
            if let Err(e) = self.swarm.behaviour_mut().kad.bootstrap() {
                println!("[Validator] Fallo al iniciar el proceso de bootstrap de Kademlia: {:?}", e);
            } else {
                println!("[Validator] Proceso de bootstrap iniciado.");
            }
        } else {
            println!("[Validator] No hay nodos bootstrap Kademlia configurados.");
        }

        // Marcar direcciones directas si están configuradas
        for addr in &self.dial_addrs {
            println!("[Validator] Marcando dirección inicial: {}", addr);
            if let Err(e) = self.swarm.dial(addr.clone()) {
                println!("[Validator] Fallo al marcar dirección {}: {:?}", addr, e);
            }
        }
    }
}
