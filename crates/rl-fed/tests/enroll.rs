//! Enrollment and the agent stream over real TLS on loopback (§21.8
//! enrollment criteria).

use std::time::Duration;

use rl_fed::client::{self, Identity, ServerAddr};
use rl_fed::registry::{Registry, TOKEN_TTL_MS};
use rl_fed::server::{self, AgentEvent, AgentListener, ServerOptions};
use rl_fed::token::Token;

struct Lab {
    server_dir: tempfile::TempDir,
    listener: AgentListener,
    addr: ServerAddr,
}

async fn lab() -> Lab {
    let server_dir = tempfile::tempdir().unwrap();
    let mut opts = ServerOptions::new(
        "127.0.0.1:0".parse().unwrap(),
        server_dir.path().to_path_buf(),
        "9.9.9",
        "home",
    );
    opts.recheck = Duration::from_millis(100);
    let listener = server::bind(opts).await.unwrap();
    let addr = ServerAddr {
        host: "127.0.0.1".into(),
        port: listener.local_addr.port(),
    };
    Lab {
        server_dir,
        listener,
        addr,
    }
}

impl Lab {
    fn registry(&self) -> Registry {
        Registry::new(self.server_dir.path())
    }

    fn token(&self, name: &str) -> Token {
        let secret = self
            .registry()
            .add_token(name, TOKEN_TTL_MS, rl_fed::now_ms())
            .unwrap();
        Token {
            secret,
            ca_sha256: self.listener.ca_sha256,
        }
    }

    async fn next_event(&mut self) -> AgentEvent {
        tokio::time::timeout(Duration::from_secs(5), self.listener.events.recv())
            .await
            .expect("an event in time")
            .expect("events open")
    }
}

#[tokio::test]
async fn an_agent_enrolls_once_and_connects() {
    let mut lab = lab().await;
    let agent_dir = tempfile::tempdir().unwrap();
    let token = lab.token("plant-genk");
    let name = client::enroll(&lab.addr, &token, agent_dir.path(), "1.0.0")
        .await
        .unwrap();
    assert_eq!(name, "plant-genk");
    assert!(
        matches!(lab.next_event().await, AgentEvent::Enrolled { name, .. } if name == "plant-genk")
    );

    // The token is used up.
    let other = tempfile::tempdir().unwrap();
    let err = client::enroll(&lab.addr, &token, other.path(), "1.0.0")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("already used"), "{err}");

    let id = Identity::load(agent_dir.path()).unwrap();
    let s = client::connect(&lab.addr, &id, "1.0.0").await.unwrap();
    assert_eq!(s.name, "plant-genk");
    assert_eq!(s.server_version, "9.9.9");
    loop {
        if let AgentEvent::Connected { name, version, .. } = lab.next_event().await {
            assert_eq!(name, "plant-genk");
            assert_eq!(version, "1.0.0");
            break;
        }
    }
}

#[tokio::test]
async fn a_token_for_another_ca_does_not_trust_the_server() {
    let lab = lab().await;
    let mut token = lab.token("a");
    token.ca_sha256[0] ^= 1;
    let d = tempfile::tempdir().unwrap();
    let err = client::enroll(&lab.addr, &token, d.path(), "1")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("does not match"), "{err}");
    // The token was not spent on the wrong server's behalf.
    assert_eq!(
        lab.registry()
            .pending_tokens(rl_fed::now_ms())
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let lab = lab().await;
    let secret = lab.registry().add_token("a", 1, 0).unwrap();
    let token = Token {
        secret,
        ca_sha256: lab.listener.ca_sha256,
    };
    let d = tempfile::tempdir().unwrap();
    assert!(
        client::enroll(&lab.addr, &token, d.path(), "1")
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_servers_own_vantage_name_is_refused() {
    let lab = lab().await;
    let token = lab.token("home");
    let d = tempfile::tempdir().unwrap();
    let err = client::enroll(&lab.addr, &token, d.path(), "1")
        .await
        .unwrap_err();
    assert!(err.to_string().contains("own vantage"), "{err}");
}

#[tokio::test]
async fn revoking_ends_the_stream_and_refuses_reconnects() {
    let mut lab = lab().await;
    let d = tempfile::tempdir().unwrap();
    client::enroll(&lab.addr, &lab.token("a"), d.path(), "1")
        .await
        .unwrap();
    let id = Identity::load(d.path()).unwrap();
    let mut s = client::connect(&lab.addr, &id, "1").await.unwrap();
    assert!(lab.registry().revoke("a", rl_fed::now_ms()).unwrap());
    let end = tokio::time::timeout(Duration::from_secs(5), s.inbound.message())
        .await
        .expect("stream ends in time");
    let status = end.unwrap_err();
    assert_eq!(status.code(), tonic::Code::PermissionDenied);
    let err = client::connect(&lab.addr, &id, "1").await.unwrap_err();
    assert!(err.to_string().contains("revoked"), "{err}");
    loop {
        if let AgentEvent::Disconnected { name, reason, .. } = lab.next_event().await {
            assert_eq!(name, "a");
            assert!(reason.contains("revoked"), "{reason}");
            break;
        }
    }
}

#[tokio::test]
async fn enrolling_again_retires_the_old_certificate() {
    let lab = lab().await;
    let old = tempfile::tempdir().unwrap();
    let new = tempfile::tempdir().unwrap();
    client::enroll(&lab.addr, &lab.token("a"), old.path(), "1")
        .await
        .unwrap();
    let old_id = Identity::load(old.path()).unwrap();
    let mut s = client::connect(&lab.addr, &old_id, "1").await.unwrap();
    client::enroll(&lab.addr, &lab.token("a"), new.path(), "1")
        .await
        .unwrap();
    let end = tokio::time::timeout(Duration::from_secs(5), s.inbound.message())
        .await
        .expect("old stream ends");
    assert!(end.is_err() || matches!(end, Ok(None)));
    assert!(client::connect(&lab.addr, &old_id, "1").await.is_err());
    let new_id = Identity::load(new.path()).unwrap();
    client::connect(&lab.addr, &new_id, "1").await.unwrap();
}

#[tokio::test]
async fn a_second_connection_replaces_the_first() {
    let lab = lab().await;
    let d = tempfile::tempdir().unwrap();
    client::enroll(&lab.addr, &lab.token("a"), d.path(), "1")
        .await
        .unwrap();
    let id = Identity::load(d.path()).unwrap();
    let mut first = client::connect(&lab.addr, &id, "1").await.unwrap();
    let _second = client::connect(&lab.addr, &id, "1").await.unwrap();
    let end = tokio::time::timeout(Duration::from_secs(5), first.inbound.message())
        .await
        .expect("first stream ends");
    assert_eq!(end.unwrap_err().code(), tonic::Code::Aborted);
}

#[tokio::test]
async fn a_certificate_from_another_server_is_refused() {
    let lab_a = lab().await;
    let lab_b = lab().await;
    let d = tempfile::tempdir().unwrap();
    client::enroll(&lab_a.addr, &lab_a.token("a"), d.path(), "1")
        .await
        .unwrap();
    let id = Identity::load(d.path()).unwrap();
    // The agent does not trust server B's CA, and B does not know the agent.
    assert!(client::connect(&lab_b.addr, &id, "1").await.is_err());
}

#[tokio::test]
async fn an_unenrolled_agent_has_no_identity() {
    let d = tempfile::tempdir().unwrap();
    let err = Identity::load(d.path()).unwrap_err();
    assert!(err.to_string().contains("not enrolled"), "{err}");
}
