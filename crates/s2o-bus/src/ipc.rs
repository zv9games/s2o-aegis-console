use crate::protocol::{IpcRequest, IpcResponse, AEGIS_PIPE_NAME, AEGIS_UNIX_SOCKET};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub type RequestHandler = Arc<dyn Fn(IpcRequest) -> futures::future::BoxFuture<'static, IpcResponse> + Send + Sync + 'static>;

pub struct AegisIpcServer {
    handler: RequestHandler,
}

impl AegisIpcServer {
    pub fn new<F, Fut>(f: F) -> Self
    where
        F: Fn(IpcRequest) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = IpcResponse> + Send + 'static,
    {
        let handler: RequestHandler = Arc::new(move |req| Box::pin(f(req)));
        Self { handler }
    }

    #[cfg(windows)]
    pub async fn run_named_pipe(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::windows::named_pipe::ServerOptions;

        loop {
            let server = ServerOptions::new()
                .first_pipe_instance(false)
                .create(AEGIS_PIPE_NAME)?;

            server.connect().await?;
            let handler = self.handler.clone();

            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(server);
                let mut lines = BufReader::new(reader).lines();

                while let Ok(Some(line)) = lines.next_line().await {
                    if line.trim().is_empty() {
                        continue;
                    }

                    let response = match serde_json::from_str::<IpcRequest>(&line) {
                        Ok(req) => handler(req).await,
                        Err(e) => IpcResponse::err(0, format!("Malformed JSON request: {e}")),
                    };

                    if let Ok(mut resp_str) = serde_json::to_string(&response) {
                        resp_str.push('\n');
                        let _ = writer.write_all(resp_str.as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                }
            });
        }
    }

    #[cfg(unix)]
    pub async fn run_unix_socket(self: Arc<Self>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::UnixListener;
        let _ = std::fs::remove_file(AEGIS_UNIX_SOCKET);
        let listener = UnixListener::bind(AEGIS_UNIX_SOCKET)?;

        loop {
            let (stream, _) = listener.accept().await?;
            let handler = self.handler.clone();

            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(stream);
                let mut lines = BufReader::new(reader).lines();

                while let Ok(Some(line)) = lines.next_line().await {
                    if line.trim().is_empty() {
                        continue;
                    }

                    let response = match serde_json::from_str::<IpcRequest>(&line) {
                        Ok(req) => handler(req).await,
                        Err(e) => IpcResponse::err(0, format!("Malformed JSON request: {e}")),
                    };

                    if let Ok(mut resp_str) = serde_json::to_string(&response) {
                        resp_str.push('\n');
                        let _ = writer.write_all(resp_str.as_bytes()).await;
                        let _ = writer.flush().await;
                    }
                }
            });
        }
    }
}

pub struct AegisIpcClient;

impl AegisIpcClient {
    #[cfg(windows)]
    pub async fn call(req: &IpcRequest) -> Result<IpcResponse, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::windows::named_pipe::ClientOptions;

        let client = ClientOptions::new().open(AEGIS_PIPE_NAME)?;
        let (reader, mut writer) = tokio::io::split(client);
        let mut lines = BufReader::new(reader).lines();

        let mut req_str = serde_json::to_string(req)?;
        req_str.push('\n');
        writer.write_all(req_str.as_bytes()).await?;
        writer.flush().await?;

        if let Some(line) = lines.next_line().await? {
            let resp: IpcResponse = serde_json::from_str(&line)?;
            Ok(resp)
        } else {
            Err("Pipe closed without response".into())
        }
    }

    #[cfg(unix)]
    pub async fn call(req: &IpcRequest) -> Result<IpcResponse, Box<dyn std::error::Error + Send + Sync>> {
        use tokio::net::UnixStream;

        let stream = UnixStream::connect(AEGIS_UNIX_SOCKET).await?;
        let (reader, mut writer) = tokio::io::split(stream);
        let mut lines = BufReader::new(reader).lines();

        let mut req_str = serde_json::to_string(req)?;
        req_str.push('\n');
        writer.write_all(req_str.as_bytes()).await?;
        writer.flush().await?;

        if let Some(line) = lines.next_line().await? {
            let resp: IpcResponse = serde_json::from_str(&line)?;
            Ok(resp)
        } else {
            Err("Socket closed without response".into())
        }
    }
}
