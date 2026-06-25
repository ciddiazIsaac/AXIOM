use libp2p::{
    gossipsub, identify, kad, mdns, ping, swarm::NetworkBehaviour,
    identity::Keypair, PeerId,
};
use std::time::Duration;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

#[derive(NetworkBehaviour)]
pub struct ValidatorBehaviour {
    pub ping: ping::Behaviour,
    pub identify: identify::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub kad: kad::Behaviour<kad::store::MemoryStore>,
    pub gossipsub: gossipsub::Behaviour,
}

impl ValidatorBehaviour {
    pub fn new(local_key: &Keypair) -> Result<Self, Box<dyn std::error::Error>> {
        let local_peer_id = PeerId::from(local_key.public());

        // 1. Setup Ping
        let ping = ping::Behaviour::new(ping::Config::default());

        // 2. Setup Identify
        let identify = identify::Behaviour::new(
            identify::Config::new("axiom/1.0.0".into(), local_key.public())
                .with_agent_version("axiom-validator/0.1.0".into()),
        );

        // 3. Setup mDNS (Local discovery)
        let mdns = mdns::tokio::Behaviour::new(
            mdns::Config::default(),
            local_peer_id,
        )?;

        // 4. Setup Kademlia DHT (Internet discovery)
        let store = kad::store::MemoryStore::new(local_peer_id);
        let kad = kad::Behaviour::with_config(local_peer_id, store, kad::Config::new(kad::PROTOCOL_NAME));

        // 5. Setup Gossipsub (Message broadcast)
        // We use the hash of the message as the message ID.
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = DefaultHasher::new();
            message.data.hash(&mut s);
            gossipsub::MessageId::from(s.finish().to_string())
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(10))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .build()
            .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?;

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        ).map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?;

        // Topic for revocations
        let topic = gossipsub::IdentTopic::new("axiom/revocations/1.0.0");
        gossipsub.subscribe(&topic)?;

        Ok(Self {
            ping,
            identify,
            mdns,
            kad,
            gossipsub,
        })
    }
}
