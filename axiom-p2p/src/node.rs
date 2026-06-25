use libp2p::{
    identify, kad, mdns, noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
    identity::Keypair, swarm::SwarmEvent,
};
use futures::StreamExt;
use std::error::Error;
use std::time::Duration;
use tokio::time;
use tokio::select;

use crate::behaviour::{ValidatorBehaviour, ValidatorBehaviourEvent};

pub struct NodeConfig {
    pub local_key: Keypair,
    pub listen_addr: Multiaddr,
    pub bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
}

pub struct ValidatorNode {
    swarm: Swarm<ValidatorBehaviour>,
    bootstrap_nodes: Vec<(PeerId, Multiaddr)>,
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

        let mut node = Self {
            swarm,
            bootstrap_nodes: config.bootstrap_nodes,
        };

        // Escuchar en la dirección configurada
        node.swarm.listen_on(config.listen_addr)?;

        Ok(node)
    }

    pub async fn run(mut self) {
        // Temporizador para comprobar la conexión con otros pares cada 30 segundos
        let mut no_peer_interval = time::interval(Duration::from_secs(30));
        no_peer_interval.tick().await; // Consumir el primer tick inmediato

        let mut discovered_any = false;

        // Intentar arranque inicial si hay nodos bootstrap
        if !self.bootstrap_nodes.is_empty() {
            self.attempt_bootstrap();
        }

        loop {
            select! {
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
                                discovered_any = true;
                            }
                        }
                        SwarmEvent::Behaviour(ValidatorBehaviourEvent::Mdns(mdns::Event::Expired(list))) => {
                            for (peer_id, _multiaddr) in list {
                                println!("[Validator] mDNS expiró al par: {}", peer_id);
                            }
                        }

                        // Eventos Identify (Intercambio de info)
                        SwarmEvent::Behaviour(ValidatorBehaviourEvent::Identify(identify::Event::Received { peer_id, info })) => {
                            println!("[Validator] Identify recibido del par: {}", peer_id);
                            for addr in info.listen_addrs {
                                // Almacenamos la info de enrutamiento en Kademlia
                                self.swarm.behaviour_mut().kad.add_address(&peer_id, addr);
                            }
                            discovered_any = true;
                        }

                        // Eventos Kademlia (Descubrimiento Global / DHT)
                        SwarmEvent::Behaviour(ValidatorBehaviourEvent::Kad(kad::Event::OutboundQueryProgress { result, .. })) => {
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
                        
                        _ => {}
                    }
                }
            }
        }
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
            println!("[Validator] No hay nodos bootstrap disponibles para conectar.");
        }
    }
}
