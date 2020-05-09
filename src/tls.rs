//! Tls
//!
//! Provides tcp streams encrypted/decrypted using tls

use std::fs::File;
use std::future::Future;
use std::io::{self, BufReader, Cursor, Read};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

use futures::ready;
use hyper::server::accept::Accept;
use hyper::server::conn::{AddrIncoming, AddrStream};

use crate::transport::Transport;
use tokio_rustls::rustls::{
    AllowAnyAuthenticatedClient, NoClientAuth, RootCertStore, ServerConfig, Session, TLSError,
};

pub use crate::filters::tls::peer_certificates;

/// Represents errors that can occur building the TlsConfig
#[derive(Debug)]
pub(crate) enum TlsConfigError {
    Io(io::Error),
    /// An Error parsing the Certificate
    CertParseError,
    /// An Error parsing a Pkcs8 key
    Pkcs8ParseError,
    /// An Error parsing a Rsa key
    RsaParseError,
    /// An error from an empty key
    EmptyKey,
    /// An error from an invalid key
    InvalidKey(TLSError),
}

impl std::fmt::Display for TlsConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsConfigError::Io(err) => err.fmt(f),
            TlsConfigError::CertParseError => write!(f, "certificate parse error"),
            TlsConfigError::Pkcs8ParseError => write!(f, "pkcs8 parse error"),
            TlsConfigError::RsaParseError => write!(f, "rsa parse error"),
            TlsConfigError::EmptyKey => write!(f, "key contains no private key"),
            TlsConfigError::InvalidKey(err) => write!(f, "key contains an invalid key, {}", err),
        }
    }
}

impl std::error::Error for TlsConfigError {}

/// Builder to set the configuration for the Tls server.
pub(crate) struct TlsConfigBuilder {
    cert: Box<dyn Read + Send + Sync>,
    key: Box<dyn Read + Send + Sync>,
    client_ca: Option<Box<dyn Read + Send + Sync>>,
}

impl std::fmt::Debug for TlsConfigBuilder {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        f.debug_struct("TlsConfigBuilder").finish()
    }
}

impl TlsConfigBuilder {
    /// Create a new TlsConfigBuilder
    pub(crate) fn new() -> TlsConfigBuilder {
        TlsConfigBuilder {
            key: Box::new(io::empty()),
            cert: Box::new(io::empty()),
            client_ca: None,
        }
    }

    /// sets the Tls key via File Path, returns `TlsConfigError::IoError` if the file cannot be open
    pub(crate) fn key_path(mut self, path: impl AsRef<Path>) -> Self {
        self.key = Box::new(LazyFile {
            path: path.as_ref().into(),
            file: None,
        });
        self
    }

    /// sets the Tls key via bytes slice
    pub(crate) fn key(mut self, key: &[u8]) -> Self {
        self.key = Box::new(Cursor::new(Vec::from(key)));
        self
    }

    /// Specify the file path for the TLS certificate to use.
    pub(crate) fn cert_path(mut self, path: impl AsRef<Path>) -> Self {
        self.cert = Box::new(LazyFile {
            path: path.as_ref().into(),
            file: None,
        });
        self
    }

    /// sets the Tls certificate via bytes slice
    pub(crate) fn cert(mut self, cert: &[u8]) -> Self {
        self.cert = Box::new(Cursor::new(Vec::from(cert)));
        self
    }

    /// Specify the file path for the client CA trust anchor cert
    pub(crate) fn client_ca_path(mut self, path: impl AsRef<Path>) -> Self {
        self.client_ca = Some(Box::new(LazyFile {
            path: path.as_ref().into(),
            file: None,
        }));
        self
    }

    /// sets the client CA trust anchor cert via bytes slice
    pub(crate) fn client_ca(mut self, ca: &[u8]) -> Self {
        self.client_ca = Some(Box::new(Cursor::new(Vec::from(ca))));
        self
    }

    pub(crate) fn build(mut self) -> Result<ServerConfig, TlsConfigError> {
        let mut cert_rdr = BufReader::new(self.cert);
        let cert = tokio_rustls::rustls::internal::pemfile::certs(&mut cert_rdr)
            .map_err(|()| TlsConfigError::CertParseError)?;

        let key = {
            // convert it to Vec<u8> to allow reading it again if key is RSA
            let mut key_vec = Vec::new();
            self.key
                .read_to_end(&mut key_vec)
                .map_err(TlsConfigError::Io)?;

            if key_vec.is_empty() {
                return Err(TlsConfigError::EmptyKey);
            }

            let mut pkcs8 = tokio_rustls::rustls::internal::pemfile::pkcs8_private_keys(
                &mut key_vec.as_slice(),
            )
            .map_err(|()| TlsConfigError::Pkcs8ParseError)?;

            if !pkcs8.is_empty() {
                pkcs8.remove(0)
            } else {
                let mut rsa = tokio_rustls::rustls::internal::pemfile::rsa_private_keys(
                    &mut key_vec.as_slice(),
                )
                .map_err(|()| TlsConfigError::RsaParseError)?;

                if !rsa.is_empty() {
                    rsa.remove(0)
                } else {
                    return Err(TlsConfigError::EmptyKey);
                }
            }
        };

        let mut config = match self.client_ca {
            Some(ca) => {
                let mut ca_rdr = BufReader::new(ca);
                let mut rcs = RootCertStore { roots: vec![] };
                rcs.add_pem_file(&mut ca_rdr)
                    .map_err(|_| TlsConfigError::CertParseError)?;
                ServerConfig::new(AllowAnyAuthenticatedClient::new(rcs))
            }
            None => ServerConfig::new(NoClientAuth::new()),
        };

        config
            .set_single_cert(cert, key)
            .map_err(|err| TlsConfigError::InvalidKey(err))?;
        config.set_protocols(&["h2".into(), "http/1.1".into()]);
        Ok(config)
    }
}

struct LazyFile {
    path: PathBuf,
    file: Option<File>,
}

impl LazyFile {
    fn lazy_read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.file.is_none() {
            self.file = Some(File::open(&self.path)?);
        }

        self.file.as_mut().unwrap().read(buf)
    }
}

impl Read for LazyFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.lazy_read(buf).map_err(|err| {
            let kind = err.kind();
            io::Error::new(
                kind,
                format!("error reading file ({:?}): {}", self.path.display(), err),
            )
        })
    }
}

impl Transport for TlsStream {
    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }
    fn peer_certificates(&self) -> Option<Vec<Vec<u8>>> {
        match self.state {
            State::Handshaking(ref _accept) => {
                println!("in handshaking");
                None
            }
            State::Streaming(ref stream) => {
                println!("in streaming");
                let (_, sess) = stream.get_ref();
                sess.get_peer_certificates()
                    .map(|v| v.into_iter().map(|c| c.0).collect())
            }
        }
    }
}

enum State {
    Handshaking(tokio_rustls::Accept<AddrStream>),
    Streaming(tokio_rustls::server::TlsStream<AddrStream>),
}

// tokio_rustls::server::TlsStream doesn't expose constructor methods,
// so we have to TlsAcceptor::accept and handshake to have access to it
// TlsStream implements AsyncRead/AsyncWrite handshaking tokio_rustls::Accept first
pub(crate) struct TlsStream {
    state: State,
    remote_addr: SocketAddr,
}

impl TlsStream {
    fn new(stream: AddrStream, config: Arc<ServerConfig>) -> TlsStream {
        let remote_addr = stream.remote_addr();
        let accept = tokio_rustls::TlsAcceptor::from(config.clone()).accept(stream);
        TlsStream {
            state: State::Handshaking(accept),
            remote_addr,
        }
    }
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        println!("reading 1");
        let pin = self.get_mut();
        println!("reading 2");
        match pin.state {
            State::Handshaking(ref mut accept) => {
                println!("reading 3");
                match ready!(Pin::new(accept).poll(cx)) {
                    Ok(mut stream) => {
                        println!("reading, handshaking, OK");
                        let result = Pin::new(&mut stream).poll_read(cx, buf);
                        pin.state = State::Streaming(stream);
                        result
                    }
                    Err(err) => {
                        println!("reading, err: {}", err);
                        Poll::Ready(Err(err))
                    }
                }
            }
            State::Streaming(ref mut stream) => {
                println!("reading, streaming");
                Pin::new(stream).poll_read(cx, buf)
            }
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        println!("writing, buf: {:?}", buf);
        let pin = self.get_mut();
        match pin.state {
            State::Handshaking(ref mut accept) => match ready!(Pin::new(accept).poll(cx)) {
                Ok(mut stream) => {
                    println!("writing, handshaking, OK");
                    let result = Pin::new(&mut stream).poll_write(cx, buf);
                    pin.state = State::Streaming(stream);
                    result
                }
                Err(err) => {
                    println!("writing, handshaking, err: {}", err);
                    Poll::Ready(Err(err))
                }
            },
            State::Streaming(ref mut stream) => {
                println!("writing, streaming");
                Pin::new(stream).poll_write(cx, buf)
            }
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.state {
            State::Handshaking(_) => Poll::Ready(Ok(())),
            State::Streaming(ref mut stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

pub(crate) struct TlsAcceptor {
    config: Arc<ServerConfig>,
    incoming: AddrIncoming,
}

impl TlsAcceptor {
    pub(crate) fn new(config: ServerConfig, incoming: AddrIncoming) -> TlsAcceptor {
        TlsAcceptor {
            config: Arc::new(config),
            incoming,
        }
    }
}

impl Accept for TlsAcceptor {
    type Conn = TlsStream;
    type Error = io::Error;

    fn poll_accept(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Self::Conn, Self::Error>>> {
        let pin = self.get_mut();
        match ready!(Pin::new(&mut pin.incoming).poll_accept(cx)) {
            Some(Ok(sock)) => Poll::Ready(Some(Ok(TlsStream::new(sock, pin.config.clone())))),
            Some(Err(e)) => Poll::Ready(Some(Err(e))),
            None => Poll::Ready(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_cert_key() {
        TlsConfigBuilder::new()
            .key_path("examples/tls/key.rsa")
            .cert_path("examples/tls/cert.pem")
            .build()
            .unwrap();
    }

    #[test]
    fn bytes_cert_key() {
        let key = include_str!("../examples/tls/key.rsa");
        let cert = include_str!("../examples/tls/cert.pem");

        TlsConfigBuilder::new()
            .key(key.as_bytes())
            .cert(cert.as_bytes())
            .build()
            .unwrap();
    }
}
