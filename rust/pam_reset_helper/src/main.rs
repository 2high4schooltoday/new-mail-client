use contracts::pam::{
    read_frame, safe_log_value, validate_request, write_frame, Request, Response, CODE_ERROR,
    CODE_OK, MAX_FRAME_SIZE,
};
#[cfg(target_os = "linux")]
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::unistd::{chown, Gid, Uid};
use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use thiserror::Error;
use wait_timeout::ChildExt;
use zeroize::{Zeroize, Zeroizing};

#[derive(Debug, Clone)]
struct Config {
    socket_path: PathBuf,
    socket_group_id: Option<u32>,
    allowed_uid: Option<u32>,
    allowed_gid: Option<u32>,
    io_timeout: Duration,
    command_timeout: Duration,
    socket_file_perms: u32,
}

#[derive(Debug, Error)]
enum HelperError {
    #[error("{0}")]
    Message(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Nix(#[from] nix::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn main() {
    if let Err(err) = run() {
        eprintln!("pam reset helper failed: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), HelperError> {
    let cfg = Arc::new(Config::from_env()?);
    let listener = bind_listener(&cfg)?;
    println!(
        "starting pam reset helper on {}",
        cfg.socket_path.to_string_lossy()
    );

    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                let cfg = Arc::clone(&cfg);
                thread::spawn(move || {
                    let _ = handle_connection(stream, &cfg);
                });
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(HelperError::Io(err)),
        }
    }
}

impl Config {
    fn from_env() -> Result<Self, HelperError> {
        let socket_path_raw = env_var(
            "PAM_RESET_HELPER_SOCKET",
            "/run/mailclient/pam-reset-helper.sock",
        );
        let socket_path = PathBuf::from(socket_path_raw.trim());
        if socket_path.as_os_str().is_empty() {
            return Err(HelperError::Message(
                "PAM_RESET_HELPER_SOCKET must not be empty".to_string(),
            ));
        }

        let timeout_sec = parse_positive_u64("PAM_RESET_HELPER_TIMEOUT_SEC", 5)?;
        let allowed_uid = parse_optional_id("PAM_RESET_ALLOWED_UID", -1)?;
        let allowed_gid = parse_optional_id("PAM_RESET_ALLOWED_GID", -1)?;

        Ok(Self {
            socket_path,
            socket_group_id: allowed_gid,
            allowed_uid,
            allowed_gid,
            io_timeout: Duration::from_secs(timeout_sec),
            command_timeout: Duration::from_secs(timeout_sec),
            socket_file_perms: 0o660,
        })
    }
}

fn env_var(key: &str, default: &str) -> String {
    match env::var(key) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => default.to_string(),
    }
}

fn parse_positive_u64(key: &str, default: u64) -> Result<u64, HelperError> {
    match env::var(key) {
        Ok(v) => {
            let parsed: u64 = v
                .trim()
                .parse()
                .map_err(|_| HelperError::Message(format!("{key} must be a positive integer")))?;
            if parsed == 0 {
                return Err(HelperError::Message(format!("{key} must be > 0")));
            }
            Ok(parsed)
        }
        Err(_) => Ok(default),
    }
}

fn parse_optional_id(key: &str, default: i64) -> Result<Option<u32>, HelperError> {
    let raw = env::var(key).unwrap_or_else(|_| default.to_string());
    let parsed: i64 = raw
        .trim()
        .parse()
        .map_err(|_| HelperError::Message(format!("{key} must be an integer")))?;
    if parsed < 0 {
        Ok(None)
    } else {
        Ok(Some(parsed as u32))
    }
}

fn bind_listener(cfg: &Config) -> Result<UnixListener, HelperError> {
    let parent = cfg
        .socket_path
        .parent()
        .ok_or_else(|| HelperError::Message("invalid socket path".to_string()))?;
    fs::create_dir_all(parent)?;

    if cfg.socket_path.exists() {
        fs::remove_file(&cfg.socket_path)?;
    }

    let listener = UnixListener::bind(&cfg.socket_path)?;
    fs::set_permissions(
        &cfg.socket_path,
        fs::Permissions::from_mode(cfg.socket_file_perms),
    )?;

    if let Some(gid) = cfg.socket_group_id {
        chown(
            &cfg.socket_path,
            Some(Uid::from_raw(0)),
            Some(Gid::from_raw(gid)),
        )?;
    }
    Ok(listener)
}

fn handle_connection(mut stream: UnixStream, cfg: &Config) -> Result<(), HelperError> {
    stream.set_read_timeout(Some(cfg.io_timeout))?;
    stream.set_write_timeout(Some(cfg.io_timeout))?;

    if authorize_peer(&stream, cfg).is_err() {
        let _ = write_response(
            &mut stream,
            Response {
                request_id: String::new(),
                ok: false,
                code: "unauthorized_peer".to_string(),
            },
        );
        return Ok(());
    }

    let mut frame = match read_frame(&mut stream, MAX_FRAME_SIZE) {
        Ok(payload) => payload,
        Err(_) => {
            let _ = write_response(
                &mut stream,
                Response {
                    request_id: String::new(),
                    ok: false,
                    code: "invalid_frame".to_string(),
                },
            );
            return Ok(());
        }
    };

    let parsed: Result<Request, _> = serde_json::from_slice(&frame);
    frame.zeroize();

    let mut req = match parsed {
        Ok(req) => req,
        Err(_) => {
            let _ = write_response(
                &mut stream,
                Response {
                    request_id: String::new(),
                    ok: false,
                    code: "invalid_request".to_string(),
                },
            );
            return Ok(());
        }
    };

    if validate_request(&req).is_err() {
        let _ = write_response(
            &mut stream,
            Response {
                request_id: req.request_id.trim().to_string(),
                ok: false,
                code: "invalid_request".to_string(),
            },
        );
        req.new_password.zeroize();
        return Ok(());
    }

    let result_code = if run_chpasswd(
        req.username.trim(),
        req.new_password.as_bytes(),
        cfg.command_timeout,
    )
    .is_ok()
    {
        CODE_OK.to_string()
    } else {
        CODE_ERROR.to_string()
    };

    req.new_password.zeroize();

    println!(
        "pam_reset_helper request_id={} username={} result_code={}",
        safe_log_value(&req.request_id),
        safe_log_value(&req.username),
        result_code
    );

    let ok = result_code == CODE_OK;
    let _ = write_response(
        &mut stream,
        Response {
            request_id: req.request_id,
            ok,
            code: result_code,
        },
    );

    Ok(())
}

fn authorize_peer(stream: &UnixStream, cfg: &Config) -> Result<(), HelperError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = stream;
        if cfg.allowed_uid.is_some() || cfg.allowed_gid.is_some() {
            return Err(HelperError::Message(
                "peer credential checks require Linux".to_string(),
            ));
        }
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        let creds = getsockopt(stream, PeerCredentials)?;
        let uid = creds.uid();
        let gid = creds.gid();

        if let Some(allowed_uid) = cfg.allowed_uid {
            if uid != allowed_uid {
                return Err(HelperError::Message(format!("uid {uid} is not allowed")));
            }
        }
        if let Some(allowed_gid) = cfg.allowed_gid {
            if gid != allowed_gid {
                return Err(HelperError::Message(format!("gid {gid} is not allowed")));
            }
        }
        Ok(())
    }
}

fn run_chpasswd(username: &str, password: &[u8], timeout: Duration) -> Result<(), HelperError> {
    let mut payload = Zeroizing::new(Vec::with_capacity(username.len() + password.len() + 2));
    payload.extend_from_slice(username.as_bytes());
    payload.push(b':');
    payload.extend_from_slice(password);
    payload.push(b'\n');

    let mut child = Command::new("/usr/sbin/chpasswd")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(&payload)?;
    }
    drop(child.stdin.take());

    match child.wait_timeout(timeout)? {
        Some(status) if status.success() => Ok(()),
        Some(_) => Err(HelperError::Message("chpasswd failed".to_string())),
        None => {
            let _ = child.kill();
            let _ = child.wait();
            Err(HelperError::Message("chpasswd timeout".to_string()))
        }
    }
}

fn write_response(stream: &mut UnixStream, resp: Response) -> Result<(), HelperError> {
    let payload = serde_json::to_vec(&resp)?;
    write_frame(stream, &payload).map_err(HelperError::Message)
}

#[allow(dead_code)]
fn _socket_path_display(path: &Path) -> String {
    path.to_string_lossy().to_string()
}
