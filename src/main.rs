use argh::FromArgs;
use rustls::client::ServerCertVerifier;
use std::{sync::Arc, time::Duration, net::ToSocketAddrs};

use itertools::Itertools;

use std::io::Write;
use std::net::TcpStream;

use anyhow::{Context, Result, anyhow};

use x509_parser::prelude::*;

//TODO: maybe use https://github.com/rusticata/tls-parser

/// TLS client to extract data from servers
#[derive(FromArgs, Debug)]
struct Args {
    #[argh(positional)]
    domain: String,

    /// port to try the TLS handshake
    #[argh(default = "443", option)]
    port: u16,

    /// check validity of the certificates
    #[argh(default = "false", option)]
    validity: bool,

    /// displays all information gathered via TLS in JSON format
    #[argh(default = "false", option)]
    all: bool,

    /// timeout for the TCP socket
    #[argh(default = "10", option)]
    timeout: u32,
}

struct Validator {}

impl ServerCertVerifier for Validator {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        //println!("{:?}", server_name);
        Ok(rustls::client::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        //println!("{:?}", dss);
        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::Certificate,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::HandshakeSignatureValid, rustls::Error> {
        //println!("{:?}", dss);
        Ok(rustls::client::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        use rustls::SignatureScheme;
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            //
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            //
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            //
            SignatureScheme::ED448,
            SignatureScheme::ED25519,
        ]
    }

    fn request_scts(&self) -> bool {
        true
    }
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();

    let root_store = rustls::RootCertStore::empty();

    //let cfg = rustls::client::DangerousClientConfig::from

    let mut config = rustls::ClientConfig::builder()
        .with_cipher_suites(&[rustls::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256])
        .with_kx_groups(&[&rustls::kx_group::X25519])
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(Validator {}));

    let domain = args
        .domain
        .as_str()
        .try_into()
        .context("While parsing domain")?;
    let url = format!("{}:{}", args.domain, args.port);
    let sock_addrs = url.to_socket_addrs()?;

    let mut conn = rustls::ClientConnection::new(Arc::new(config), domain)
        .context("While stabilishing connection")?;

    let mut sock = TcpStream::connect_timeout(&sock_addrs.last().ok_or(anyhow!("Cant resolve domain"))?, Duration::from_secs(args.timeout.into()))
        .context("While connecting socket")?;

    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    tls.write_all(
        format!(
            "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept-Encoding: identity\r\n\r\n",
            args.domain
        )
        .as_bytes(),
    )
    .context("While sending data")?;

    let certs = tls.conn.peer_certificates();
    if let Some(certs) = certs {
        certs
            .into_iter()
            .for_each(|c| match X509Certificate::from_der(&c.0) {
                Ok((_, cer)) => {
                    //println!("Issuer: {}", cer.issuer());
                    //println!("Subject: {}", cer.subject());
                    //println!("Valid: {}", cer.validity().is_valid());
                    if let Ok(Some(BasicExtension {
                        value:
                            SubjectAlternativeName {
                                general_names: names,
                            },
                        ..
                    })) = cer.subject_alternative_name()
                    {
                        println!(
                            "{}",
                            names
                                .into_iter()
                                .map(|x| match x {
                                    GeneralName::DNSName(domain) => domain.to_string(),
                                    _ => format!("{}", x),
                                })
                                .sorted()
                                .dedup()
                                .collect::<Vec<_>>()
                                .join("\n")
                        );
                    }
                }
                _ => {}
            })
    }

    Ok(())
}
