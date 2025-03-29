use dryoc::{
    constants::{CRYPTO_BOX_BEFORENMBYTES, CRYPTO_BOX_PUBLICKEYBYTES, CRYPTO_BOX_SECRETKEYBYTES},
    dryocbox::protected::{HeapByteArray, Locked, LockedRO},
    precalc::PrecalcSecretKey,
    types::{ByteArray, NewByteArray},
};
use scc::HashMap;
use std::{fmt::Debug, sync::Arc};
use tokio::time::{self, Duration, Instant};

type StoredSessionKey = PrecalcSecretKey<LockedRO<HeapByteArray<CRYPTO_BOX_BEFORENMBYTES>>>;
type SessionKey = Locked<HeapByteArray<CRYPTO_BOX_BEFORENMBYTES>>;

struct Session(StoredSessionKey, Instant);

#[derive(Debug, thiserror::Error)]
#[error("can't precalculate session key: {0}")]
pub struct PrecalcSessionKeyError(#[from] std::io::Error);

pub struct SessionBox {
    map: Arc<HashMap<[u8; CRYPTO_BOX_PUBLICKEYBYTES], Session>>,
    tti: Duration,
}

impl SessionBox {
    pub fn new(time_to_idle: Duration, cleanup_interval: Duration) -> Self {
        let cache = Self {
            map: Arc::new(HashMap::new()),
            tti: time_to_idle,
        };

        let map_weak = Arc::downgrade(&cache.map);
        tokio::spawn(async move {
            let mut interval = time::interval(cleanup_interval);
            loop {
                interval.tick().await;

                if let Some(map) = map_weak.upgrade() {
                    let now = Instant::now();
                    map.retain_async(|_, Session(_, last_access)| now - *last_access <= cache.tti)
                        .await;

                    continue;
                }

                return;
            }
        });

        cache
    }

    pub async fn get_or_generate_session_key<
        ThirdPartyPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>,
        SecretKey: ByteArray<CRYPTO_BOX_SECRETKEYBYTES>,
    >(
        &self,
        public_key: &ThirdPartyPublicKey,
        secret_key: &SecretKey,
    ) -> Result<SessionKey, PrecalcSessionKeyError> {
        if let Some(session_key) = self.get_session_key(public_key).await {
            Ok(session_key)
        } else {
            let precalc = StoredSessionKey::precalculate_readonly_locked(public_key, secret_key)?;

            let mut session_key_buf = Locked::new_byte_array();
            session_key_buf.clone_from_slice(&precalc);

            _ = self
                .map
                .insert_async(
                    public_key.as_array().clone(),
                    Session(precalc, Instant::now()),
                )
                .await;

            Ok(session_key_buf)
        }
    }

    pub async fn get_session_key<ThirdPartyPublicKey: ByteArray<CRYPTO_BOX_PUBLICKEYBYTES>>(
        &self,
        public_key: &ThirdPartyPublicKey,
    ) -> Option<SessionKey> {
        if let Some(mut entry) = self.map.get_async(public_key.as_array()).await {
            let Session(session_key, last_access) = entry.get_mut();

            *last_access = Instant::now();

            let mut session_key_buf = Locked::new_byte_array();
            session_key_buf.clone_from_slice(&session_key);

            Some(session_key_buf)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use dryoc::keypair::KeyPair;
    use tokio::time::Duration;

    #[tokio::test]
    async fn test_eviction() {
        let cache = SessionBox::new(Duration::from_secs(0), Duration::from_millis(100));
        let mut last_keypair = KeyPair::gen_with_defaults();
        for _ in 0..1000 {
            let keypair = KeyPair::gen_with_defaults();
            _ = cache
                .get_or_generate_session_key(&keypair.public_key, &keypair.secret_key)
                .await
                .unwrap();

            last_keypair = keypair;
        }

        tokio::time::sleep(Duration::from_millis(200)).await;

        assert!(cache
            .get_session_key(&last_keypair.public_key)
            .await
            .is_none())
    }
}
