use bhttp::{Message, Mode};
use ohttp::ClientRequest;
use reqwest::{Client, StatusCode};

/// Parsed response from an OHTTP-decapsulated Binary HTTP message.
#[derive(Debug)]
pub struct OhttpResponse {
    pub status: StatusCode,
    pub body: Vec<u8>,
}

/// Sends an HTTP request through an OHTTP relay and returns the decapsulated response.
///
/// The request is encoded as a Binary HTTP message (RFC 9292), encrypted via
/// OHTTP (RFC 9458), POSTed to the relay, then the response is decrypted and
/// parsed back into status + body.
pub async fn ohttp_request(
    client: &Client,
    relay_url: &str,
    key_config: &[u8],
    method: &[u8],
    authority: &str,
    path: &str,
    body: Option<&[u8]>,
) -> Result<OhttpResponse, OhttpError> {
    let mut msg = Message::request(
        method.to_vec(),
        b"https".to_vec(),
        authority.as_bytes().to_vec(),
        path.as_bytes().to_vec(),
    );
    if let Some(body) = body {
        msg.put_header("content-type", "application/json");
        msg.write_content(body);
    }
    let mut bhttp_buf = Vec::new();
    msg.write_bhttp(Mode::KnownLength, &mut bhttp_buf)?;

    let ohttp_req = ClientRequest::from_encoded_config_list(key_config)?;
    let (enc_request, ohttp_resp_ctx) = ohttp_req.encapsulate(&bhttp_buf)?;

    let resp = client
        .post(relay_url)
        .header("content-type", "message/ohttp-req")
        .body(enc_request)
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(OhttpError::RelayError {
            status: resp.status(),
            body: resp.text().await.unwrap_or_default(),
        });
    }

    let enc_response = resp.bytes().await?;
    let response_buf = ohttp_resp_ctx.decapsulate(&enc_response)?;

    let response_msg = Message::read_bhttp(&mut std::io::Cursor::new(&response_buf))?;
    let status_code = response_msg
        .control()
        .status()
        .map(|s| s.code())
        .ok_or(OhttpError::MissingResponseStatus)?;
    let status =
        StatusCode::from_u16(status_code).map_err(|_| bhttp::Error::InvalidStatus)?;

    Ok(OhttpResponse {
        status,
        body: response_msg.content().to_vec(),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum OhttpError {
    #[error("OHTTP encapsulation error: {0}")]
    Ohttp(#[from] ohttp::Error),

    #[error("Binary HTTP error: {0}")]
    Bhttp(#[from] bhttp::Error),

    #[error("HTTP transport error: {0}")]
    Network(#[from] reqwest::Error),

    #[error("OHTTP relay error (status {status}): {body}")]
    RelayError { status: StatusCode, body: String },

    #[error("OHTTP response missing HTTP status line")]
    MissingResponseStatus,
}
