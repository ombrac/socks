use std::io;
use std::sync::Arc;
use std::time::Duration;

use crate::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use crate::net::TcpListener;
use crate::v5::{Method, Request, Stream};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Config<A, H> {
    auth: A,
    handler: H,
    timeout: Duration,
}

impl<A, H> Config<A, H> {
    pub fn new(auth: A, handler: H) -> Self {
        Self {
            auth,
            handler,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

/// SOCKS5 server implementation
pub struct Server;

impl Server {
    pub async fn run<H, A>(
        listener: TcpListener,
        config: Arc<Config<A, H>>,
        shutdown_signal: impl Future<Output = ()>,
    ) -> io::Result<()>
    where
        H: Handler + 'static,
        A: Authenticator + 'static,
    {
        tokio::pin!(shutdown_signal);

        loop {
            tokio::select! {
                // Bias select to prefer the shutdown signal if both are ready
                biased;

                _ = &mut shutdown_signal => return Ok(()),

                result = listener.accept() => {
                    let (inner, addr) = match result {
                        Ok(res) => res,
                        Err(_err) => {
                            #[cfg(feature = "tracing")]
                            tracing::error!("Failed to accept connection: {}", _err);
                            continue;
                        }
                    };

                    let local_addr = match inner.local_addr() {
                        Ok(addr) => addr,
                        Err(_err) => {
                            #[cfg(feature = "tracing")]
                            tracing::error!("Failed to get local address for connection {}: {}", addr, _err);
                            continue;
                        }
                    };

                    let config = config.clone();
                    tokio::spawn(async move {
                        let mut stream = Stream::with(inner, addr, local_addr);

                        if let Err(_err) = Self::handle_connection(&mut stream, &config).await {
                            #[cfg(feature = "tracing")]
                            tracing::warn!("Connection {} error: {}", addr, _err);
                        }
                    });
                }
            }
        }
    }

    async fn handle_connection<H, A, S>(
        stream: &mut Stream<S>,
        config: &Config<A, H>,
    ) -> io::Result<()>
    where
        H: Handler + 'static,
        A: Authenticator + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + Sync,
    {
        // Apply timeout to handshake phase
        let request = tokio::time::timeout(config.timeout, async {
            let methods = stream.read_methods().await?;
            config.auth.auth(stream, methods).await?;
            stream.read_request().await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Timeout during authentication"))??;

        config.handler.handle(stream, request).await
    }
}

/// Authentication trait for SOCKS5 server
pub trait Authenticator: Send + Sync {
    fn auth<T>(
        &self,
        stream: &mut Stream<T>,
        methods: Vec<Method>,
    ) -> impl Future<Output = io::Result<()>> + Send
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync;
}

/// Request handler trait for SOCKS5 server
pub trait Handler: Send + Sync {
    fn handle<T>(
        &self,
        stream: &mut Stream<T>,
        request: Request,
    ) -> impl Future<Output = io::Result<()>> + Send
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + Sync;
}

pub mod auth {
    use super::*;

    pub struct NoAuthentication;

    impl Authenticator for NoAuthentication {
        async fn auth<T>(&self, stream: &mut Stream<T>, _methods: Vec<Method>) -> io::Result<()>
        where
            T: AsyncRead + AsyncWrite + Unpin + Send + Sync,
        {
            stream.write_auth_method(Method::NoAuthentication).await?;
            Ok(())
        }
    }

    pub struct UserPassword {
        username: String,
        password: String,
    }

    impl UserPassword {
        pub fn new(username: String, password: String) -> Self {
            Self { username, password }
        }
    }

    impl Authenticator for UserPassword {
        async fn auth<T>(&self, stream: &mut Stream<T>, methods: Vec<Method>) -> io::Result<()>
        where
            T: AsyncRead + AsyncWrite + Unpin + Send + Sync,
        {
            if !methods.contains(&Method::UsernamePassword) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Username/Password authentication required",
                ));
            }

            stream.write_auth_method(Method::UsernamePassword).await?;

            // Read username/password subnegotiation
            let version = stream.read_u8().await?;
            if version != 0x01 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid subnegotiation version",
                ));
            }

            let ulen = stream.read_u8().await?;
            let mut username = vec![0; ulen as usize];
            stream.read_exact(&mut username).await?;

            let plen = stream.read_u8().await?;
            let mut password = vec![0; plen as usize];
            stream.read_exact(&mut password).await?;

            // Verify credentials
            if username != self.username.as_bytes() || password != self.password.as_bytes() {
                stream.write_all(&[0x01, 0x01]).await?;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Invalid username or password",
                ));
            }

            stream.write_all(&[0x01, 0x00]).await?;

            Ok(())
        }
    }
}
