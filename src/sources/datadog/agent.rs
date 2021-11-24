use crate::{
    codecs,
    event::Event,
    internal_events::HttpDecompressError,
    sources::datadog::{logs, traces},
    sources::util::ErrorMessage,
    Pipeline,
};
use bytes::{Buf, Bytes};
use flate2::read::{MultiGzDecoder, ZlibDecoder};
use futures::{SinkExt, StreamExt, TryFutureExt};
use http::StatusCode;
use regex::Regex;
use serde::{Deserialize, Serialize};
use snafu::Snafu;
use std::{io::Read, sync::Arc};
use vector_core::event::{BatchNotifier, BatchStatus};
use warp::{filters::BoxedFilter, reject::Rejection, reply::Response, Filter, Reply};

#[derive(Clone, Copy, Debug, Snafu)]
pub(crate) enum ApiError {
    BadRequest,
    InvalidDataFormat,
    ServerShutdown,
}

impl warp::reject::Reject for ApiError {}

#[derive(Deserialize)]
pub struct ApiKeyQueryParams {
    #[serde(rename = "dd-api-key")]
    pub dd_api_key: Option<String>,
}

#[derive(Clone)]
pub(crate) struct DatadogAgentSource {
    acknowledgements: bool,
    api_key_extractor: ApiKeyExtractor,
    decoder: codecs::Decoder,
    out: Pipeline,
}

#[derive(Clone)]
pub struct ApiKeyExtractor {
    matcher: Regex,
    store_api_key: bool,
}

impl ApiKeyExtractor {
    pub fn extract(
        &self,
        path: &str,
        header: Option<String>,
        query_params: Option<String>,
    ) -> Option<Arc<str>> {
        if !self.store_api_key {
            return None;
        }
        // Grab from URL first
        self.matcher
            .captures(path)
            .and_then(|cap| cap.name("api_key").map(|key| key.as_str()).map(Arc::from))
            // Try from query params
            .or_else(|| query_params.map(Arc::from))
            // Try from header next
            .or_else(|| header.map(Arc::from))
    }
}

impl DatadogAgentSource {
    pub(crate) fn new(
        acknowledgements: bool,
        out: Pipeline,
        store_api_key: bool,
        decoder: codecs::Decoder,
    ) -> Self {
        Self {
            acknowledgements,
            api_key_extractor: ApiKeyExtractor {
                store_api_key,
                matcher: Regex::new(r"^/v1/input/(?P<api_key>[[:alnum:]]{32})/??")
                    .expect("static regex always compiles"),
            },
            decoder,
            out,
        }
    }

    pub(crate) fn build_warp_filters(
        &self,
        logs: bool,
        traces: bool,
    ) -> crate::Result<BoxedFilter<(Response,)>> {
        let mut filters = logs.then(|| {
            logs::build_warp_filter(
                self.acknowledgements,
                self.out.clone(),
                self.api_key_extractor.clone(),
                self.decoder.clone(),
            )
        });

        if traces {
            let trace_filter = traces::build_warp_filter(
                self.acknowledgements,
                self.out.clone(),
                self.api_key_extractor.clone(),
            );
            filters = filters
                .map(|f| f.or(trace_filter.clone()).unify().boxed())
                .or(Some(trace_filter));
        }

        /*
        if metrics {
            let metrics_filter = new_builder(...).build());
            filters = filters
                .map(|f| f.or(metrics_filter.clone()).unify().boxed())
                .or(Some(metrics_filter));
        }
        */

        filters.ok_or("At least one of the supported data type shall be enabled".into())
    }
}

pub(crate) async fn handle_request(
    events: Result<Vec<Event>, ErrorMessage>,
    acknowledgements: bool,
    mut out: Pipeline,
) -> Result<Response, Rejection> {
    match events {
        Ok(mut events) => {
            let receiver = BatchNotifier::maybe_apply_to_events(acknowledgements, &mut events);

            let mut events = futures::stream::iter(events).map(Ok);
            out.send_all(&mut events)
                .map_err(move |error: crate::pipeline::ClosedError| {
                    // can only fail if receiving end disconnected, so we are shutting down,
                    // probably not gracefully.
                    error!(message = "Failed to forward events, downstream is closed.");
                    error!(message = "Tried to send the following event.", %error);
                    warp::reject::custom(ApiError::ServerShutdown)
                })
                .await?;
            match receiver {
                None => Ok(warp::reply().into_response()),
                Some(receiver) => match receiver.await {
                    BatchStatus::Delivered => Ok(warp::reply().into_response()),
                    BatchStatus::Errored => Err(warp::reject::custom(ErrorMessage::new(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Error delivering contents to sink".into(),
                    ))),
                    BatchStatus::Failed => Err(warp::reject::custom(ErrorMessage::new(
                        StatusCode::BAD_REQUEST,
                        "Contents failed to deliver to sink".into(),
                    ))),
                },
            }
        }
        Err(err) => Err(warp::reject::custom(err)),
    }
}

pub(crate) fn decode(header: &Option<String>, mut body: Bytes) -> Result<Bytes, ErrorMessage> {
    if let Some(encodings) = header {
        for encoding in encodings.rsplit(',').map(str::trim) {
            body = match encoding {
                "identity" => body,
                "gzip" | "x-gzip" => {
                    let mut decoded = Vec::new();
                    MultiGzDecoder::new(body.reader())
                        .read_to_end(&mut decoded)
                        .map_err(|error| handle_decode_error(encoding, error))?;
                    decoded.into()
                }
                "deflate" | "x-deflate" => {
                    let mut decoded = Vec::new();
                    ZlibDecoder::new(body.reader())
                        .read_to_end(&mut decoded)
                        .map_err(|error| handle_decode_error(encoding, error))?;
                    decoded.into()
                }
                encoding => {
                    return Err(ErrorMessage::new(
                        StatusCode::UNSUPPORTED_MEDIA_TYPE,
                        format!("Unsupported encoding {}", encoding),
                    ))
                }
            }
        }
    }
    //emit!(&DatadogAgentRequestReceived {
    //    byte_size: body.len(),
    //    count: 1,
    //}); => to be dropped and replaced by
    // emit!(&HttpBytesReceived {
    //    byte_size: body.len(),
    //    http_path: path.as_str(),
    //   protocol: self.protocol,
    // });
    Ok(body)
}

fn handle_decode_error(encoding: &str, error: impl std::error::Error) -> ErrorMessage {
    emit!(&HttpDecompressError {
        encoding,
        error: &error
    });
    ErrorMessage::new(
        StatusCode::UNPROCESSABLE_ENTITY,
        format!("Failed decompressing payload with {} decoder.", encoding),
    )
}

// https://github.com/DataDog/datadog-agent/blob/a33248c2bc125920a9577af1e16f12298875a4ad/pkg/logs/processor/json.go#L23-L49
#[derive(Deserialize, Clone, Serialize, Debug)]
#[serde(deny_unknown_fields)]
struct LogMsg {
    pub message: Bytes,
    pub status: Bytes,
    pub timestamp: i64,
    pub hostname: Bytes,
    pub service: Bytes,
    pub ddsource: Bytes,
    pub ddtags: Bytes,
}
