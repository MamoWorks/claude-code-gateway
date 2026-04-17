use rustls::craft::{
    CraftExtension, ExtensionSpec, Fingerprint, GreaseOrCipher, GreaseOrCurve, GreaseOrVersion,
    KeepExtension,
};
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::enums::{ECPointFormat, ExtensionType, PSKKeyExchangeMode};
use rustls::internal::msgs::handshake::ClientExtension;
use rustls::{CipherSuite, Error, NamedGroup, ProtocolVersion, RootCertStore, SignatureScheme};
use static_init::dynamic;
use std::sync::Arc;
use std::time::Duration;

// ---------------------------------------------------------------------------
// X25519MLKEM768 混合密钥交换（真实实现）
// 按 draft-ietf-tls-ecdhe-mlkem：
//   client key_share = ML-KEM encaps key (1184) || X25519 pub (32) = 1216 bytes
//   server key_share = ML-KEM ciphertext (1088) || X25519 pub (32) = 1120 bytes
//   shared_secret    = ML-KEM shared secret (32) || X25519 shared (32) = 64 bytes
// ---------------------------------------------------------------------------
const X25519MLKEM768_GROUP: NamedGroup = NamedGroup::Unknown(0x11EC);

#[derive(Debug)]
struct X25519Mlkem768KxGroup;

impl SupportedKxGroup for X25519Mlkem768KxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        use ml_kem::{EncodedSizeUser, KemCore, MlKem768};

        let mut rng = rand::thread_rng();

        // ML-KEM-768 keypair
        let (dk, ek) = MlKem768::generate(&mut rng);
        let ek_bytes = &ek.as_bytes();

        // X25519 keypair
        let x25519_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rng);
        let x25519_public = x25519_dalek::PublicKey::from(&x25519_secret);

        // client key_share = ek (1184) || x25519_pub (32)
        let mut pub_key = Vec::with_capacity(1216);
        pub_key.extend_from_slice(ek_bytes);
        pub_key.extend_from_slice(x25519_public.as_bytes());

        Ok(Box::new(X25519Mlkem768ActiveKx {
            dk,
            x25519_secret,
            pub_key,
        }))
    }

    fn name(&self) -> NamedGroup {
        X25519MLKEM768_GROUP
    }
}

struct X25519Mlkem768ActiveKx {
    dk: ml_kem::kem::DecapsulationKey<ml_kem::MlKem768Params>,
    x25519_secret: x25519_dalek::StaticSecret,
    pub_key: Vec<u8>,
}

impl std::fmt::Debug for X25519Mlkem768ActiveKx {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519Mlkem768ActiveKx").finish()
    }
}

impl ActiveKeyExchange for X25519Mlkem768ActiveKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        use ml_kem::kem::Decapsulate as _;

        // server key_share = ciphertext (1088) || x25519_pub (32) = 1120 bytes
        if peer_pub_key.len() != 1120 {
            return Err(Error::General(format!(
                "X25519MLKEM768: invalid server key_share length {}",
                peer_pub_key.len()
            )));
        }

        let (ct_bytes, x25519_peer) = peer_pub_key.split_at(1088);

        // ML-KEM decapsulation
        let ct: ml_kem::Ciphertext<ml_kem::MlKem768> = ct_bytes
            .try_into()
            .map_err(|_| Error::General("ML-KEM: invalid ciphertext".into()))?;
        let mlkem_ss = self
            .dk
            .decapsulate(&ct)
            .map_err(|_| Error::General("ML-KEM decapsulation failed".into()))?;

        // X25519 DH
        let x25519_peer_key: [u8; 32] = x25519_peer
            .try_into()
            .map_err(|_| Error::General("X25519: invalid peer key".into()))?;
        let x25519_peer_pub = x25519_dalek::PublicKey::from(x25519_peer_key);
        let x25519_ss = self.x25519_secret.diffie_hellman(&x25519_peer_pub);

        // shared_secret = mlkem_ss (32) || x25519_ss (32)
        let mut shared = Vec::with_capacity(64);
        shared.extend_from_slice(mlkem_ss.as_ref());
        shared.extend_from_slice(x25519_ss.as_bytes());

        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        X25519MLKEM768_GROUP
    }
}

// X448 fake group（ring 不支持，只声明不使用）
#[derive(Debug)]
struct FakeKxGroup(NamedGroup);

impl SupportedKxGroup for FakeKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        Err(Error::General(format!(
            "key exchange not supported for {:?}",
            self.0
        )))
    }
    fn name(&self) -> NamedGroup {
        self.0
    }
}

static X25519MLKEM768_KX: X25519Mlkem768KxGroup = X25519Mlkem768KxGroup;
static FAKE_X448: FakeKxGroup = FakeKxGroup(NamedGroup::Unknown(0x001E));

macro_rules! static_ref {
    ($val:expr, $type:ty) => {{
        static X: $type = $val;
        X
    }};
}

// ---------------------------------------------------------------------------
// Node.js 密码套件（52 个，与 tls.peet.ws 实测对齐）
// ---------------------------------------------------------------------------
#[dynamic]
pub static NODEJS_CIPHER: Vec<GreaseOrCipher> = vec![
    GreaseOrCipher::T(CipherSuite::TLS13_AES_256_GCM_SHA384),
    GreaseOrCipher::T(CipherSuite::TLS13_CHACHA20_POLY1305_SHA256),
    GreaseOrCipher::T(CipherSuite::TLS13_AES_128_GCM_SHA256),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC02F)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC02B)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC030)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC02C)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x009E)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC027)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x0067)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC028)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x006B)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x00A3)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x009F)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xCCA9)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xCCA8)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xCCAA)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC0AD)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC09F)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC05D)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC061)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC057)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC053)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x00A2)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC0AC)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC09E)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC05C)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC060)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC056)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC052)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC024)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x006A)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC023)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x0040)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC00A)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC014)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x0039)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x0038)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC009)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC013)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x0033)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x0032)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x009D)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC09D)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC051)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x009C)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC09C)),
    GreaseOrCipher::T(CipherSuite::Unknown(0xC050)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x003D)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x003C)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x0035)),
    GreaseOrCipher::T(CipherSuite::Unknown(0x002F)),
];

// ---------------------------------------------------------------------------
// Node.js 扩展列表（12 个，精确顺序匹配 tls.peet.ws 实测）
// ---------------------------------------------------------------------------
#[dynamic]
pub static NODEJS_EXTENSION: Vec<ExtensionSpec> = {
    use ExtensionSpec::*;
    use KeepExtension::*;
    vec![
        // 1. renegotiation_info (65281)
        Craft(CraftExtension::RenegotiationInfo),
        // 2. server_name (0)
        Keep(Must(ExtensionType::ServerName)),
        // 3. ec_point_formats (11)
        Rustls(ClientExtension::EcPointFormats(vec![
            ECPointFormat::Uncompressed,
            ECPointFormat::ANSIX962CompressedPrime,
            ECPointFormat::ANSIX962CompressedChar2,
        ])),
        // 4. supported_groups (10)
        Rustls(ClientExtension::NamedGroups(vec![
            NamedGroup::Unknown(0x11EC), // X25519MLKEM768
            NamedGroup::X25519,
            NamedGroup::secp256r1,
            NamedGroup::Unknown(0x001E), // X448
            NamedGroup::secp384r1,
            NamedGroup::secp521r1,
            NamedGroup::FFDHE2048,
            NamedGroup::FFDHE3072,
        ])),
        // 5. session_ticket (35)
        Keep(OrDefault(
            ExtensionType::SessionTicket,
            ClientExtension::SessionTicket(
                rustls::internal::msgs::handshake::ClientSessionTicket::Offer(Payload(vec![])),
            ),
        )),
        // 6. ALPN (16)
        Craft(CraftExtension::Protocols(&[b"http/1.1"])),
        // 7. encrypt_then_mac (22)
        Rustls(ClientExtension::Unknown(
            rustls::internal::msgs::handshake::UnknownExtension {
                typ: ExtensionType::Unknown(22),
                payload: Payload(vec![]),
            },
        )),
        // 8. extended_master_secret (23)
        Rustls(ClientExtension::ExtendedMasterSecretRequest),
        // 9. signature_algorithms (13)
        Rustls(ClientExtension::SignatureAlgorithms(vec![
            SignatureScheme::Unknown(0x0905),
            SignatureScheme::Unknown(0x0906),
            SignatureScheme::Unknown(0x0904),
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::Unknown(0x0603),
            SignatureScheme::Unknown(0x0807),
            SignatureScheme::Unknown(0x0808),
            SignatureScheme::Unknown(0x081a),
            SignatureScheme::Unknown(0x081b),
            SignatureScheme::Unknown(0x081c),
            SignatureScheme::Unknown(0x0809),
            SignatureScheme::Unknown(0x080a),
            SignatureScheme::Unknown(0x080b),
            SignatureScheme::Unknown(0x0804),
            SignatureScheme::Unknown(0x0805),
            SignatureScheme::Unknown(0x0806),
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::Unknown(0x0303),
            SignatureScheme::Unknown(0x0301),
            SignatureScheme::Unknown(0x0302),
            SignatureScheme::Unknown(0x0402),
            SignatureScheme::Unknown(0x0502),
            SignatureScheme::Unknown(0x0602),
        ])),
        // 10. supported_versions (43)
        Craft(CraftExtension::SupportedVersions(static_ref!(
            &[
                GreaseOrVersion::T(ProtocolVersion::TLSv1_3),
                GreaseOrVersion::T(ProtocolVersion::TLSv1_2),
            ],
            &[GreaseOrVersion]
        ))),
        // 11. psk_key_exchange_modes (45)
        Rustls(ClientExtension::PresharedKeyModes(vec![
            PSKKeyExchangeMode::PSK_DHE_KE,
        ])),
        // 12. key_share (51)
        Craft(CraftExtension::KeyShare(&[GreaseOrCurve::T(
            NamedGroup::X25519,
        )])),
    ]
};

#[dynamic]
pub static NODEJS_FINGERPRINT: Fingerprint = Fingerprint {
    extensions: &NODEJS_EXTENSION,
    cipher: &NODEJS_CIPHER,
    shuffle_extensions: false,
};

/// 构建带 Node.js TLS 指纹的 rustls ClientConfig。
fn build_tls_config() -> rustls::ClientConfig {
    let root_store = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth()
        .with_fingerprint(NODEJS_FINGERPRINT.builder());

    // 将 supported_groups 中声明但 ring 不支持的 group 注册为 fake KxGroup，
    // 确保 HRR 验证时 find_kx_group() 能找到它们。
    let mut provider = config.provider.as_ref().clone();
    provider.kx_groups.insert(0, &X25519MLKEM768_KX);
    provider.kx_groups.push(&FAKE_X448);
    config.provider = Arc::new(provider);

    config
}

/// 上游读取 idle 超时：两次 body 数据帧之间最多等这么久。
/// - 流式 SSE：每来一个事件就重置，只要还在持续吐 event 就不会被切
/// - 非流式：headers 到后 body 若 300s 内一个字节都没来视为上游卡死
/// 与旧版 `.timeout(300)`（完整生命周期硬顶）的区别：不再因流持续时间长而误切
const UPSTREAM_READ_TIMEOUT: Duration = Duration::from_secs(300);

/// 创建带 TLS 指纹伪装的 reqwest 客户端。
/// 支持直连和代理（HTTP/SOCKS5）。
pub fn make_request_client(proxy_url: &str) -> reqwest::Client {
    make_request_client_with_read_timeout(proxy_url, UPSTREAM_READ_TIMEOUT)
}

/// 内部构造函数：暴露 read_timeout 参数给测试用短值验证 idle 语义。
fn make_request_client_with_read_timeout(
    proxy_url: &str,
    read_timeout: Duration,
) -> reqwest::Client {
    let tls_config = build_tls_config();

    let mut builder = reqwest::Client::builder()
        .use_preconfigured_tls(tls_config)
        .read_timeout(read_timeout)
        .no_proxy();

    if !proxy_url.is_empty() {
        if let Ok(proxy) = reqwest::Proxy::all(proxy_url) {
            builder = builder.proxy(proxy);
        }
    }

    builder.build().unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
mod tests {
    //! 动态验证 `.read_timeout()` 的 idle 语义：
    //! 真起一个本地 axum 服务器，按指定节奏吐 chunk；再用我们的 client 用短超时请求，
    //! 观察"密集小 gap"是否能跨越总超时、"长 idle"是否触发超时。

    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::response::IntoResponse;
    use axum::routing::get;
    use bytes::Bytes;
    use futures_util::StreamExt;
    use std::convert::Infallible;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::net::TcpListener;
    use tokio::sync::oneshot;
    use tokio::time::Instant;

    /// 在 127.0.0.1:随机端口启动一个 axum server：
    /// - GET /stream?chunks=N&gap_ms=G  → 先立即吐 1 字节 header，再按 G ms 间隔吐 N 个 chunk
    /// - GET /hang?gap_ms=G             → 吐 1 字节后无限等待
    ///
    /// 返回 (SocketAddr, 关闭信号的 sender)。drop sender 时 server 会优雅退出。
    async fn spawn_server() -> (SocketAddr, oneshot::Sender<()>) {
        async fn stream_handler(
            axum::extract::Query(q): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >,
        ) -> impl IntoResponse {
            let chunks: usize = q.get("chunks").and_then(|s| s.parse().ok()).unwrap_or(5);
            let gap_ms: u64 = q.get("gap_ms").and_then(|s| s.parse().ok()).unwrap_or(50);
            let stream = async_stream::stream! {
                // 先吐一个引导字节，让 headers 立刻可读
                yield Ok::<Bytes, Infallible>(Bytes::from_static(b"."));
                for i in 0..chunks {
                    tokio::time::sleep(Duration::from_millis(gap_ms)).await;
                    let payload = format!("chunk-{}\n", i);
                    yield Ok::<Bytes, Infallible>(Bytes::from(payload));
                }
            };
            Body::from_stream(stream)
        }

        async fn hang_handler(
            axum::extract::Query(q): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >,
        ) -> impl IntoResponse {
            let pre_hang_gap: u64 = q
                .get("pre_hang_gap_ms")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let stream = async_stream::stream! {
                yield Ok::<Bytes, Infallible>(Bytes::from_static(b"start"));
                if pre_hang_gap > 0 {
                    tokio::time::sleep(Duration::from_millis(pre_hang_gap)).await;
                    yield Ok::<Bytes, Infallible>(Bytes::from_static(b"second"));
                }
                // 永远挂着
                tokio::time::sleep(Duration::from_secs(3600)).await;
                yield Ok::<Bytes, Infallible>(Bytes::from_static(b"never"));
            };
            Body::from_stream(stream)
        }

        let app = Router::new()
            .route("/stream", get(stream_handler))
            .route("/hang", get(hang_handler));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            let server = axum::serve(listener, app);
            tokio::select! {
                _ = server => {},
                _ = rx => {},
            }
        });
        (addr, tx)
    }

    /// 读取流并累计总字节，直到流结束或出错。返回 (字节数, 耗时, 错误)。
    async fn drain_stream(
        resp: reqwest::Response,
    ) -> (usize, Duration, Option<reqwest::Error>) {
        let start = Instant::now();
        let mut total = 0usize;
        let mut stream = resp.bytes_stream();
        let mut err = None;
        while let Some(r) = stream.next().await {
            match r {
                Ok(b) => total += b.len(),
                Err(e) => {
                    err = Some(e);
                    break;
                }
            }
        }
        (total, start.elapsed(), err)
    }

    #[tokio::test]
    async fn idle_timeout_does_not_fire_when_chunks_arrive_within_window() {
        // read_timeout=300ms；server 每 50ms 吐 1 个，共 10 个，总耗时 ~500ms > timeout。
        // 旧的 .timeout(300ms) 语义下会被切；新的 .read_timeout(300ms) 不应切。
        let (addr, _stop) = spawn_server().await;
        let client =
            make_request_client_with_read_timeout("", Duration::from_millis(300));
        let url = format!("http://{}/stream?chunks=10&gap_ms=50", addr);

        let resp = client.get(&url).send().await.expect("headers ok");
        assert!(resp.status().is_success());

        let (bytes, elapsed, err) = drain_stream(resp).await;
        assert!(err.is_none(), "idle 语义下流不应被切：err={:?}", err);
        // 总字节应 > 引导字节的 1，证明 chunk 都收到了
        assert!(
            bytes > "chunk-0\n".len() * 5,
            "chunk 到达数异常: bytes={}",
            bytes
        );
        assert!(
            elapsed >= Duration::from_millis(400),
            "总耗时应 > 单 gap 许多倍，证明确实持续了 >300ms: elapsed={:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn idle_timeout_fires_when_upstream_hangs() {
        // read_timeout=150ms；server 吐第一个 chunk 后永远挂住。
        // client 应收到第一个 chunk，然后在 ~150ms 后错误退出。
        let (addr, _stop) = spawn_server().await;
        let client =
            make_request_client_with_read_timeout("", Duration::from_millis(150));
        let url = format!("http://{}/hang", addr);

        let resp = client.get(&url).send().await.expect("headers ok");
        let (bytes, elapsed, err) = drain_stream(resp).await;

        let err = err.expect("hang 后必须收到错误");
        assert!(err.is_timeout() || format!("{:?}", err).to_lowercase().contains("time"),
                "错误类型应为 timeout：{:?}", err);
        // 第一个 chunk "start" = 5 字节 + 引导字节 "." = 6
        assert!(bytes >= 1, "至少应收到首个引导/chunk: bytes={}", bytes);
        // 触发时机：first frame 之后 ~150ms 内应被切
        assert!(
            elapsed >= Duration::from_millis(140) && elapsed <= Duration::from_millis(2000),
            "超时应在 ~150ms 附近触发: elapsed={:?}",
            elapsed
        );
    }

    #[tokio::test]
    async fn idle_timeout_resets_between_frames() {
        // 更精细：read_timeout=200ms，gap=150ms，吐 8 个 chunk，总耗时 >1.2s。
        // 每个 gap 都 < timeout；如果 reset 正常就能全收；如果没 reset 就早挂。
        let (addr, _stop) = spawn_server().await;
        let client =
            make_request_client_with_read_timeout("", Duration::from_millis(200));
        let url = format!("http://{}/stream?chunks=8&gap_ms=150", addr);

        let resp = client.get(&url).send().await.expect("headers ok");
        let (bytes, elapsed, err) = drain_stream(resp).await;

        assert!(err.is_none(), "read_timeout 应在每个 frame 后 reset: err={:?}", err);
        // 总耗时证明确实跨越了多个 timeout window（150ms*8 = 1.2s > 200ms 单窗）
        assert!(
            elapsed >= Duration::from_millis(1000),
            "总耗时应 ~1.2s 证明 reset 生效: elapsed={:?}",
            elapsed
        );
        assert!(bytes > 50, "应收到全部 chunk: bytes={}", bytes);

        // 防止未使用变量告警
        let _ = Arc::new(());
    }
}
