use super::Direction;
use crate::AppResult;
use reqwest::Url;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Provider {
    Cloudflare,
    UserOwnedHttp { origin: String },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderInfo {
    pub id: String,
    pub origin: String,
    pub serverSelection: String,
    pub protocol: String,
    pub privacyNotice: String,
    pub documentation: String,
}

impl Provider {
    fn origin(&self) -> AppResult<Url> {
        let value = match self {
            Self::Cloudflare => "https://speed.cloudflare.com/",
            Self::UserOwnedHttp { origin } => origin,
        };
        if value.len() > 2048 {
            return Err("Benchmark origin is too long".into());
        }
        let url = Url::parse(value)?;
        let loopback = url
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
            || url.host().is_none()
            || url.port() == Some(0)
            || (url.scheme() != "https" && !(url.scheme() == "http" && loopback))
        {
            return Err("Use an HTTPS server origin without credentials, path, query, or fragment; plain HTTP is limited to literal loopback addresses".into());
        }
        Ok(url)
    }

    pub fn info(&self) -> AppResult<ProviderInfo> {
        let origin = self.origin()?.to_string();
        let (id, serverSelection, privacyNotice, documentation) = match self {
            Self::Cloudflare => (
                "cloudflare",
                "Anycast-selected edge; no fixed city is guaranteed",
                "Cloudflare receives your IP address and test traffic under its privacy policy. No application results-logging request is sent.",
                "https://github.com/cloudflare/speedtest#api-reference",
            ),
            Self::UserOwnedHttp { .. } => (
                "userOwnedHttp",
                "Explicit user-owned server origin",
                "Only use a server you own or have permission to benchmark. The server receives your IP address and synthetic test traffic.",
                "docs/transfer-protocol.md",
            ),
        };
        Ok(ProviderInfo {
            id: id.into(),
            origin,
            serverSelection: serverSelection.into(),
            protocol: "HTTP/1.1 application payload goodput".into(),
            privacyNotice: privacyNotice.into(),
            documentation: documentation.into(),
        })
    }

    pub(super) fn requestUrl(&self, direction: Direction, bytes: u64) -> AppResult<Url> {
        let mut url = self.origin()?;
        let path = match (self, direction) {
            (Self::Cloudflare, Direction::Download) => "/__down",
            (Self::Cloudflare, Direction::Upload) => "/__up",
            (Self::UserOwnedHttp { .. }, Direction::Download) => "/epp/v1/download",
            (Self::UserOwnedHttp { .. }, Direction::Upload) => "/epp/v1/upload",
        };
        url.set_path(path);
        if direction == Direction::Download || matches!(self, Self::Cloudflare) {
            url.query_pairs_mut()
                .append_pair("bytes", &bytes.to_string());
        }
        Ok(url)
    }
}
