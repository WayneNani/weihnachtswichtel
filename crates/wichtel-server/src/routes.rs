//! HTTP routes (docs/api.md).

use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::rejection::{BytesRejection, JsonRejection, PathRejection};
use axum::extract::{
    ConnectInfo, DefaultBodyLimit, FromRequest, FromRequestParts, Path, Request, State,
};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::Response;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::routing::{get, post, put};
use axum::{Json, Router, middleware};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use futures_util::{Stream, StreamExt, stream};
use serde::de::DeserializeOwned;
use tokio::sync::broadcast::error::RecvError;
use wichtel_api::{
    CONTENT_TYPE_BINARY, CreateGroupRequest, CreateGroupResponse, ErrorCode, Fixed, GroupView,
    HEADER_SIGNATURE, JoinRequest, JoinResponse, PushSubscriptionRequest, RevealRelease,
    ScheduleRequest, UpdateEvent, VapidKeyResponse,
};
use wichtel_core::{N_MAX, roles_vector_len};

use crate::app::App;
use crate::error::{ApiError, ApiResult};
use crate::web;

/// Limit for JSON bodies (docs/api.md).
pub const JSON_LIMIT: usize = 16 * 1024;
/// Limit for role vectors: `L_V(N_MAX)`.
pub const ROLES_LIMIT: usize = roles_vector_len(N_MAX);

type AppState = State<Arc<App>>;

/// Build the complete router (API, static assets, middleware).
pub fn router(app: Arc<App>) -> Router {
    Router::new()
        .route("/api/health", get(|| async { "ok" }))
        .route("/api/push/vapid-key", get(vapid_key))
        .route("/api/groups", post(create_group))
        .route("/api/groups/{gid}", get(get_group).delete(delete_group))
        .route("/api/groups/{gid}/schedule", put(set_schedule))
        .route("/api/groups/{gid}/start", post(start))
        .route("/api/groups/{gid}/restart", post(restart))
        .route("/api/groups/{gid}/participants", post(join))
        .route(
            "/api/groups/{gid}/participants/{pid}",
            put(update_participant).delete(leave),
        )
        .route(
            "/api/groups/{gid}/participants/{pid}/push",
            put(push_subscribe).delete(push_unsubscribe),
        )
        .route(
            "/api/groups/{gid}/rounds/{r}/roles",
            put(upload_roles)
                .layer(DefaultBodyLimit::max(ROLES_LIMIT))
                .get(get_roles),
        )
        .route(
            "/api/groups/{gid}/rounds/{r}/reveal",
            put(upload_reveal).get(get_reveal),
        )
        .route("/api/groups/{gid}/events", get(events))
        .layer(DefaultBodyLimit::max(JSON_LIMIT))
        .fallback(web::static_handler)
        .layer(middleware::from_fn(web::log_requests))
        .layer(middleware::from_fn(web::security_headers))
        .with_state(app)
}

// ---------------------------------------------------------------- extractors & parsing

fn decode_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    let v = URL_SAFE_NO_PAD.decode(s).ok()?;
    v.try_into().ok()
}

fn parse_id(s: &str) -> ApiResult<[u8; 16]> {
    decode_fixed::<16>(s).ok_or_else(ApiError::not_found)
}

/// `Authorization: Bearer <base64url(32 B)>`; anything else is treated as absent.
fn bearer(headers: &HeaderMap) -> Option<[u8; 32]> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    decode_fixed::<32>(token.trim())
}

/// `X-Wichtel-Signature: <base64url(64 B)>`.
fn signature(headers: &HeaderMap) -> ApiResult<Option<[u8; 64]>> {
    match headers.get(HEADER_SIGNATURE) {
        None => Ok(None),
        Some(v) => v
            .to_str()
            .ok()
            .and_then(|s| decode_fixed::<64>(s.trim()))
            .map(Some)
            .ok_or(ApiError::bad_request("malformed signature header")),
    }
}

/// Path parameters with JSON errors.
pub struct Params<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for Params<T> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiError> {
        Path::<T>::from_request_parts(parts, state)
            .await
            .map(|Path(t)| Params(t))
            .map_err(|_: PathRejection| ApiError::bad_request("invalid path"))
    }
}

/// JSON body with JSON errors.
pub struct JsonBody<T>(pub T);

impl<S: Send + Sync, T: DeserializeOwned> FromRequest<S> for JsonBody<T> {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        Json::<T>::from_request(req, state)
            .await
            .map(|Json(t)| JsonBody(t))
            .map_err(|rej: JsonRejection| match rej.status() {
                StatusCode::PAYLOAD_TOO_LARGE => {
                    ApiError::new(ErrorCode::PayloadTooLarge, "body too large")
                }
                StatusCode::UNSUPPORTED_MEDIA_TYPE => {
                    ApiError::bad_request("expected application/json")
                }
                _ => ApiError::bad_request("invalid JSON body"),
            })
    }
}

/// Raw binary body with JSON errors.
pub struct RawBody(pub Bytes);

impl<S: Send + Sync> FromRequest<S> for RawBody {
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, ApiError> {
        Bytes::from_request(req, state)
            .await
            .map(RawBody)
            .map_err(|rej: BytesRejection| match rej.status() {
                StatusCode::PAYLOAD_TOO_LARGE => {
                    ApiError::new(ErrorCode::PayloadTooLarge, "body too large")
                }
                _ => ApiError::bad_request("cannot read body"),
            })
    }
}

/// Client IP for rate limiting only (never logged or stored). Behind a trusted reverse proxy
/// (`WICHTEL_TRUST_PROXY`) the last `X-Forwarded-For` entry is used.
pub struct ClientIp(pub Option<IpAddr>);

impl FromRequestParts<Arc<App>> for ClientIp {
    type Rejection = Infallible;

    async fn from_request_parts(parts: &mut Parts, app: &Arc<App>) -> Result<Self, Infallible> {
        if app.cfg.trust_proxy
            && let Some(ip) = parts
                .headers
                .get_all("x-forwarded-for")
                .iter()
                .next_back()
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.rsplit(',').next())
                .and_then(|v| v.trim().parse().ok())
        {
            return Ok(ClientIp(Some(ip)));
        }
        Ok(ClientIp(
            parts
                .extensions
                .get::<ConnectInfo<SocketAddr>>()
                .map(|c| c.0.ip()),
        ))
    }
}

// ---------------------------------------------------------------- handlers

async fn vapid_key(State(app): AppState) -> Json<VapidKeyResponse> {
    Json(VapidKeyResponse {
        public_key: wichtel_api::Bin(app.vapid.public_key().to_vec()),
    })
}

async fn create_group(
    State(app): AppState,
    ClientIp(ip): ClientIp,
    JsonBody(req): JsonBody<CreateGroupRequest>,
) -> ApiResult<(StatusCode, Json<CreateGroupResponse>)> {
    let gid = app.create_group(ip, req).await?;
    Ok((
        StatusCode::CREATED,
        Json(CreateGroupResponse { gid: Fixed(gid) }),
    ))
}

async fn get_group(
    State(app): AppState,
    Params(gid): Params<String>,
) -> ApiResult<Json<GroupView>> {
    Ok(Json(app.view(&parse_id(&gid)?).await?))
}

async fn delete_group(
    State(app): AppState,
    Params(gid): Params<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    app.delete_group(parse_id(&gid)?, bearer(&headers)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn set_schedule(
    State(app): AppState,
    Params(gid): Params<String>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<ScheduleRequest>,
) -> ApiResult<StatusCode> {
    app.set_schedule(parse_id(&gid)?, bearer(&headers), req.draw_at)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn start(
    State(app): AppState,
    Params(gid): Params<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    app.start(parse_id(&gid)?, bearer(&headers)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn restart(
    State(app): AppState,
    Params(gid): Params<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    app.restart(parse_id(&gid)?, bearer(&headers)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn join(
    State(app): AppState,
    ClientIp(ip): ClientIp,
    Params(gid): Params<String>,
    JsonBody(req): JsonBody<JoinRequest>,
) -> ApiResult<(StatusCode, Json<JoinResponse>)> {
    let pid = app.join(parse_id(&gid)?, ip, req).await?;
    Ok((StatusCode::CREATED, Json(JoinResponse { pid: Fixed(pid) })))
}

async fn update_participant(
    State(app): AppState,
    Params((gid, pid)): Params<(String, String)>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<JoinRequest>,
) -> ApiResult<StatusCode> {
    app.update_participant(parse_id(&gid)?, parse_id(&pid)?, bearer(&headers), req)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn leave(
    State(app): AppState,
    Params((gid, pid)): Params<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    app.leave(parse_id(&gid)?, parse_id(&pid)?, bearer(&headers))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn push_subscribe(
    State(app): AppState,
    Params((gid, pid)): Params<(String, String)>,
    headers: HeaderMap,
    JsonBody(req): JsonBody<PushSubscriptionRequest>,
) -> ApiResult<StatusCode> {
    app.push_subscribe(parse_id(&gid)?, parse_id(&pid)?, bearer(&headers), req)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn push_unsubscribe(
    State(app): AppState,
    Params((gid, pid)): Params<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    app.push_unsubscribe(parse_id(&gid)?, parse_id(&pid)?, bearer(&headers))
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn upload_roles(
    State(app): AppState,
    Params((gid, r)): Params<(String, u32)>,
    headers: HeaderMap,
    RawBody(body): RawBody,
) -> ApiResult<StatusCode> {
    let sig = signature(&headers)?;
    app.upload_roles(parse_id(&gid)?, r, bearer(&headers), sig, &body)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_roles(
    State(app): AppState,
    Params((gid, r)): Params<(String, u32)>,
) -> ApiResult<Response> {
    let data = app.roles_result(parse_id(&gid)?, r).await?;
    let mut res = Response::new(axum::body::Body::from(data));
    res.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(CONTENT_TYPE_BINARY),
    );
    Ok(res)
}

async fn upload_reveal(
    State(app): AppState,
    Params((gid, r)): Params<(String, u32)>,
    headers: HeaderMap,
    RawBody(body): RawBody,
) -> ApiResult<StatusCode> {
    let sig = signature(&headers)?;
    app.upload_reveal(parse_id(&gid)?, r, bearer(&headers), sig, &body)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn get_reveal(
    State(app): AppState,
    Params((gid, r)): Params<(String, u32)>,
) -> ApiResult<Json<RevealRelease>> {
    Ok(Json(app.reveal_release(parse_id(&gid)?, r).await?))
}

fn sse_event(ev: &UpdateEvent) -> Event {
    Event::default()
        .event("update")
        .data(serde_json::to_string(ev).expect("UpdateEvent serializes"))
}

async fn events(
    State(app): AppState,
    Params(gid): Params<String>,
) -> ApiResult<Sse<impl Stream<Item = Result<Event, Infallible>>>> {
    let gid = parse_id(&gid)?;
    let (initial, rx) = app.subscribe(&gid).await?;
    let first = stream::once(async move { Ok(sse_event(&initial)) });
    let rest = stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => return Some((Ok(sse_event(&ev)), rx)),
                // Clients refetch on every event; skipping lagged ones is harmless.
                Err(RecvError::Lagged(_)) => continue,
                Err(RecvError::Closed) => return None,
            }
        }
    });
    Ok(Sse::new(first.chain(rest)).keep_alive(KeepAlive::default()))
}
