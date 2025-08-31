use crate::views;
use ama_core::Context;
// use async_stream::stream;
use axum::{
    Router,
    extract::State,
    response::{
        Html,
        Json,
        // sse::{Event, Sse},
    },
    routing::get,
};
// use futures_core::Stream;
use serde_json::Value;
use std::sync::Arc;
// use std::{convert::Infallible, time::Duration};
// use tokio::time::interval;

pub fn router(ctx: Arc<Context>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/json", get(peers_json))
        // .route("/stream", get(stream_peers))
        .with_state(ctx)
}

async fn index(State(ctx): State<Arc<Context>>) -> Html<String> {
    let peers = ctx.get_peers().await;
    Html(views::peers::page(&peers))
}

async fn peers_json(State(ctx): State<Arc<Context>>) -> Json<Value> {
    let peers = ctx.get_peers().await;
    Json(serde_json::to_value(peers).unwrap_or_default())
}
//
// async fn stream_peers(State(ctx): State<Arc<Context>>) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
//     let stream = stream! {
//         let mut ticker = interval(Duration::from_millis(100));
//         loop {
//             ticker.tick().await;
//             let snapshot = { ctx.get_peers().await };
//             let json = serde_json::to_string(&snapshot).unwrap();
//             yield Ok(Event::default().data(json));
//         }
//     };
//     Sse::new(stream)
// }
