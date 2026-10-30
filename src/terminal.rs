//! Web terminal: a PTY-backed shell over WebSocket (admin only).
//!
//! Protocol:
//! - client → server, text frames (JSON):
//!   `{"type":"auth","csrf":"…"}` (must be first, within 10 s),
//!   `{"type":"input","data":"…"}`, `{"type":"resize","cols":N,"rows":N}`
//! - server → client: binary frames with raw PTY output; a text frame
//!   `{"type":"exit"}` when the shell ends.
//!
//! The upgrade request is authenticated by cookie + Origin (in `Authed`), and the
//! first message must carry the session's CSRF token.

use crate::web::{Admin, Shared, err};
use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde::Deserialize;
use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::time::Duration;

const MAX_TERMINALS: usize = 8;

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum ClientMsg {
    Auth { csrf: String },
    Input { data: String },
    Resize { cols: u16, rows: u16 },
}

pub async fn handler(State(st): State<Shared>, Admin(a): Admin, ws: WebSocketUpgrade) -> Response {
    if !crate::web::terminal_available(&st) {
        return err(StatusCode::FORBIDDEN, "terminal is disabled");
    }
    if st.terminals.fetch_add(1, Ordering::SeqCst) >= MAX_TERMINALS {
        st.terminals.fetch_sub(1, Ordering::SeqCst);
        return err(StatusCode::TOO_MANY_REQUESTS, "too many open terminals");
    }
    ws.max_message_size(64 * 1024).on_upgrade(move |socket| async move {
        st.audit.log(&a.session.user, a.ip, "terminal.open", "", true);
        if let Err(e) = session(socket, &st, &a.token, &a.session.csrf).await {
            tracing::warn!("terminal: {e:#}");
        }
        st.audit.log(&a.session.user, a.ip, "terminal.close", "", true);
        st.terminals.fetch_sub(1, Ordering::SeqCst);
    })
}

async fn session(socket: WebSocket, st: &Shared, token: &str, csrf: &str) -> anyhow::Result<()> {
    let (mut tx, mut rx) = socket.split();

    // 1. CSRF handshake.
    let first = tokio::time::timeout(Duration::from_secs(10), rx.next()).await;
    let ok = match first {
        Ok(Some(Ok(Message::Text(t)))) => matches!(
            serde_json::from_str::<ClientMsg>(&t),
            Ok(ClientMsg::Auth { csrf: c }) if subtle::ConstantTimeEq::ct_eq(c.as_bytes(), csrf.as_bytes()).into()
        ),
        _ => false,
    };
    if !ok {
        let _ = tx.send(Message::Close(None)).await;
        anyhow::bail!("terminal handshake failed");
    }

    // 2. PTY + shell with a minimal, explicit environment.
    let pty = native_pty_system().openpty(PtySize { rows: 30, cols: 100, pixel_width: 0, pixel_height: 0 })?;
    let shell = &st.cfg.terminal.shell;
    let mut cmd = CommandBuilder::new(shell);
    cmd.arg("-l");
    cmd.env_clear();
    let home = std::env::var("HOME").unwrap_or_else(|_| "/".into());
    cmd.env("HOME", &home);
    cmd.env("PATH", crate::exec::SAFE_PATH);
    cmd.env("TERM", "xterm-256color");
    cmd.env("COLORTERM", "truecolor");
    cmd.env("LANG", "C.UTF-8");
    cmd.env("SHELL", shell);
    if let Ok(u) = std::env::var("USER") {
        cmd.env("USER", u);
    }
    cmd.cwd(&home);
    let mut child = pty.slave.spawn_command(cmd)?;
    drop(pty.slave);
    let mut reader = pty.master.try_clone_reader()?;
    let mut writer = pty.master.take_writer()?;
    let master = pty.master;

    // PTY output → channel (blocking reader thread).
    let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(64);
    std::thread::spawn(move || {
        let mut buf = [0u8; 16 * 1024];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
    // Channel → PTY input (blocking writer thread).
    let (in_tx, in_rx) = std::sync::mpsc::channel::<Vec<u8>>();
    std::thread::spawn(move || {
        while let Ok(data) = in_rx.recv() {
            if writer.write_all(&data).is_err() || writer.flush().is_err() {
                break;
            }
        }
    });

    let mut check = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            out = out_rx.recv() => match out {
                Some(data) => { if tx.send(Message::Binary(data.into())).await.is_err() { break; } }
                None => { let _ = tx.send(Message::Text(r#"{"type":"exit"}"#.into())).await; break; }
            },
            msg = rx.next() => match msg {
                Some(Ok(Message::Text(t))) => match serde_json::from_str::<ClientMsg>(&t) {
                    Ok(ClientMsg::Input { data }) => {
                        // Typing counts as activity for the idle timeout.
                        st.auth.session(token);
                        let _ = in_tx.send(data.into_bytes());
                    }
                    Ok(ClientMsg::Resize { cols, rows }) => {
                        let _ = master.resize(PtySize { rows: rows.clamp(2, 500), cols: cols.clamp(2, 1000), pixel_width: 0, pixel_height: 0 });
                    }
                    _ => {}
                },
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => break,
                _ => {}
            },
            _ = check.tick() => {
                // Logout or session expiry closes open terminals too.
                if st.auth.session_peek(token).is_none() {
                    let _ = tx.send(Message::Close(None)).await;
                    break;
                }
            }
        }
    }
    let _ = child.kill();
    let _ = tokio::task::spawn_blocking(move || child.wait()).await;
    Ok(())
}
