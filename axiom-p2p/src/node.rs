use futures::StreamExt;
use libp2p::{
    gossipsub, identify, identity::Keypair, kad, mdns, noise, swarm::SwarmEvent, tcp, yamux,
    Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use std::time::Duration;
use tokio::select;
use tokio::sync::oneshot;
use tokio::time;

use crate::behaviour::{ValidatorBehaviour, ValidatorBehaviourEvent};
use crate::crdt::RevocationCrdt;
use crate::error::NodeError;
use crate::message::{GossipPayload, RevocationMessage, SignedPayload};

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
    QueryCount { response: oneshot::Sender<usize> },
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
    local_key: Keypair,
    /// Flag: si acabamos de unirnos a la red y necesitamos pedir el estado completo.
    needs_sync: bool,
}

impl ValidatorNode {
    pub fn new(config: NodeConfig) -> Result<Self, NodeError> {
        let swarm = SwarmBuilder::with_existing_identity(config.local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| NodeError::P2pError(e.to_string()))?
            .with_behaviour(|key| ValidatorBehaviour::new(key).unwrap())
            .map_err(|e| NodeError::P2pError(e.to_string()))?
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
            local_key: config.local_key,
            needs_sync: true, // Al arrancar, necesitamos sync
        };

        // Flush del estado inicial del documento Automerge para que
        // los deltas posteriores solo contengan cambios reales.
        let _ = node.crdt.save_incremental();

        // Escuchar en la dirección configurada
        node.swarm
            .listen_on(config.listen_addr)
            .map_err(|e| NodeError::P2pError(e.to_string()))?;

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
                        let _ = cmd_tx
                            .send(NodeCommand::Revoke {
                                credential_id: parts[1].to_string(),
                                issuer_did: "did:axiom:local".to_string(),
                                reason: "manual revocation".to_string(),
                            })
                            .await;
                    } else {
                        tracing::warn!("Uso: revoke <credential_id>");
                    }
                } else if cmd == "status" {
                    let (tx, rx) = oneshot::channel();
                    let _ = cmd_tx.send(NodeCommand::QueryCount { response: tx }).await;
                    if let Ok(count) = rx.await {
                        tracing::info!("Revocaciones totales en CRDT: {}", count);
                    }
                } else if !cmd.is_empty() {
                    tracing::warn!("Comando desconocido. Usa 'revoke <credential_id>' o 'status'");
                }
            }
        });

        self.run_with_commands(cmd_rx).await;
    }

    /// Ejecuta el nodo con comandos programáticos tipados.
    /// Usado directamente por tests de integración.
    pub async fn run_with_commands(
        mut self,
        mut command_rx: tokio::sync::mpsc::Receiver<NodeCommand>,
    ) {
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
                        tracing::warn!("No se descubrieron pares en los últimos 30s. Reintentando bootstrap...");
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
                            tracing::info!("Escuchando en {:?}", address);
                        }

                        // Eventos mDNS (Descubrimiento Local)
                        SwarmEvent::Behaviour(ValidatorBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                            for (peer_id, multiaddr) in list {
                                tracing::info!("mDNS descubrió al par: {}", peer_id);
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
                                tracing::debug!("mDNS expiró al par: {}", peer_id);
                            }
                        }

                        // Eventos Identify (Intercambio de info)
                        SwarmEvent::Behaviour(ValidatorBehaviourEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                            tracing::info!("Identify recibido del par: {}", peer_id);
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
                                    tracing::info!("Kademlia bootstrap exitoso");
                                    discovered_any = true;
                                }
                                kad::QueryResult::Bootstrap(Err(e)) => {
                                    tracing::warn!("Kademlia bootstrap falló: {:?}", e);
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
            NodeCommand::Revoke {
                credential_id,
                issuer_did,
                reason,
            } => {
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
                    tracing::error!("Error al publicar revocación: {:?}", e);
                }
            }
            NodeCommand::QueryCount { response } => {
                let _ = response.send(self.crdt.count());
            }
            NodeCommand::IsRevoked {
                credential_id,
                response,
            } => {
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
    /// Verifica la firma digital y, si es válida, procesa el delta incremental.
    async fn handle_gossipsub_message(&mut self, data: &[u8]) {
        let signed: SignedPayload = match serde_json::from_slice(data) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("No se pudo deserializar SignedPayload: {:?}", e);
                return;
            }
        };

        // Reconstruir la PublicKey desde los bytes provistos
        let pub_key =
            match libp2p::identity::PublicKey::try_decode_protobuf(&signed.public_key_bytes) {
                Ok(k) => k,
                Err(e) => {
                    tracing::warn!(
                        "Clave pública inválida recibida de {}: {:?}",
                        signed.sender_peer_id,
                        e
                    );
                    return;
                }
            };

        // Verificar si la clave pública coincide con el PeerId declarado
        if PeerId::from(pub_key.clone()).to_string() != signed.sender_peer_id {
            tracing::error!(
                "¡ALERTA ZERO TRUST! PeerId no coincide con la clave pública de: {}",
                signed.sender_peer_id
            );
            return;
        }

        // Verificar la firma criptográfica sobre el payload real
        if !pub_key.verify(&signed.payload_bytes, &signed.signature) {
            tracing::error!(
                "¡ALERTA ZERO TRUST! Firma criptográfica inválida rechazada de: {}",
                signed.sender_peer_id
            );
            return;
        }

        match serde_json::from_slice::<GossipPayload>(&signed.payload_bytes) {
            Ok(GossipPayload::RevocationChange(change_bytes)) => {
                tracing::info!(
                    "Cambio incremental verificado de {} ({} bytes)",
                    signed.sender_peer_id,
                    change_bytes.len()
                );
                match self.crdt.apply_incremental(&change_bytes).await {
                    Ok(()) => {
                        tracing::info!(
                            "CRDT actualizado. Total revocaciones: {}",
                            self.crdt.count()
                        );
                    }
                    Err(e) => {
                        tracing::error!("Error al aplicar cambio incremental: {:?}", e);
                    }
                }
            }
            Ok(GossipPayload::SyncRequest) => {
                tracing::info!(
                    "SyncRequest recibido de {}. Enviando estado completo...",
                    signed.sender_peer_id
                );
                let full_state = self.crdt.save_full();
                let response = GossipPayload::SyncResponse(full_state);
                if let Err(e) = self.publish_payload(&response) {
                    tracing::error!("Error al enviar SyncResponse: {:?}", e);
                }
            }
            Ok(GossipPayload::SyncResponse(full_bytes)) => {
                tracing::info!(
                    "SyncResponse verificado de {} ({} bytes). Fusionando...",
                    signed.sender_peer_id,
                    full_bytes.len()
                );
                match self.crdt.merge_full(&full_bytes).await {
                    Ok(()) => {
                        self.needs_sync = false;
                        tracing::info!(
                            "Sync completo exitoso. Total revocaciones: {}",
                            self.crdt.count()
                        );
                    }
                    Err(e) => {
                        tracing::error!("Error al fusionar estado completo: {:?}", e);
                    }
                }
            }
            Err(e) => {
                tracing::warn!("No se pudo deserializar GossipPayload validado: {:?}", e);
            }
        }
    }

    /// Publica una revocación en la red.
    ///
    /// 1. Inserta la revocación en el documento Automerge local
    /// 2. Genera el delta incremental
    /// 3. Lo envuelve en `GossipPayload::RevocationChange` y lo publica
    pub async fn publish_revocation(
        &mut self,
        revocation: &RevocationMessage,
    ) -> Result<(), NodeError> {
        // Mutar el documento Automerge local
        let is_new = self.crdt.add(revocation).await?;

        if is_new {
            tracing::info!(
                "Credencial {} revocada localmente. Propagando delta...",
                revocation.credential_id
            );
        } else {
            tracing::info!(
                "Credencial {} ya estaba revocada. Re-propagando por consistencia.",
                revocation.credential_id
            );
        }

        // Obtener el delta incremental (solo los cambios nuevos)
        let delta = self.crdt.save_incremental();
        let payload = GossipPayload::RevocationChange(delta);

        self.publish_payload(&payload)?;

        tracing::info!("Revocación publicada firmada en Gossipsub.");
        Ok(())
    }

    /// Consulta si una credencial está revocada en el estado local del CRDT.
    pub fn is_revoked(&self, credential_id: &str) -> bool {
        self.crdt.is_revoked(credential_id)
    }

    /// Solicita el estado completo del CRDT a la red.
    /// Se usa cuando un nodo se une tarde y necesita sincronizarse.
    fn request_full_sync(&mut self) {
        tracing::info!("Solicitando estado completo del CRDT a la red (SyncRequest)...");
        let payload = GossipPayload::SyncRequest;
        if let Err(e) = self.publish_payload(&payload) {
            tracing::error!("Error al enviar SyncRequest: {:?}", e);
        }
    }

    /// Publica un `GossipPayload` firmado criptográficamente en el topic.
    fn publish_payload(&mut self, payload: &GossipPayload) -> Result<(), NodeError> {
        let topic = gossipsub::IdentTopic::new("axiom/revocations/1.0.0");

        // Serializar el payload interno
        let payload_bytes = serde_json::to_vec(payload)?;

        // Firmarlo con nuestra clave privada
        let signature = self
            .local_key
            .sign(&payload_bytes)
            .map_err(|e| NodeError::Internal(format!("Error firmando: {:?}", e)))?;

        // Envolver en SignedPayload
        let signed = SignedPayload {
            sender_peer_id: self.swarm.local_peer_id().to_string(),
            public_key_bytes: self.local_key.public().encode_protobuf(),
            signature,
            payload_bytes,
        };

        // Serializar y publicar
        let data = serde_json::to_vec(&signed)?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic, data)
            .map_err(|e| NodeError::P2pError(e.to_string()))?;
        Ok(())
    }

    fn attempt_bootstrap(&mut self) {
        let mut added = false;
        for (peer, addr) in &self.bootstrap_nodes {
            tracing::info!("Añadiendo nodo bootstrap {} en {}", peer, addr);
            self.swarm
                .behaviour_mut()
                .kad
                .add_address(peer, addr.clone());
            added = true;
        }

        if added {
            if let Err(e) = self.swarm.behaviour_mut().kad.bootstrap() {
                tracing::warn!(
                    "Fallo al iniciar el proceso de bootstrap de Kademlia: {:?}",
                    e
                );
            } else {
                tracing::info!("Proceso de bootstrap iniciado.");
            }
        } else {
            tracing::info!("No hay nodos bootstrap Kademlia configurados.");
        }

        // Marcar direcciones directas si están configuradas
        for addr in &self.dial_addrs {
            tracing::info!("Marcando dirección inicial: {}", addr);
            if let Err(e) = self.swarm.dial(addr.clone()) {
                tracing::warn!("Fallo al marcar dirección {}: {:?}", addr, e);
            }
        }
    }
}
