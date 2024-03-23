use axum::{
    extract::ConnectInfo, http::StatusCode, routing::post, Error, Json, Router
};
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use tower_http::{
    services::ServeDir,
    trace::{TraceLayer},
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use std::fmt::Debug;
use axum_password_worker::PasswordWorker;
use std::process::Command;
use axum_client_ip::{InsecureClientIp, SecureClientIp, SecureClientIpSource};
use tower_http::cors::{CorsLayer};

#[tokio::main]
async fn main() {

    tracing_subscriber::registry()
    .with(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "example_static_file_server=debug,tower_http=debug".into()),
    )
    .with(tracing_subscriber::fmt::layer())
    .init();

    tokio::join!(
        serve(init_web_page(), 3000)
    );

}

async fn serve(app: Router, port: u16) {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::debug!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app.layer(TraceLayer::new_for_http()))
    .await
    .unwrap();

}


fn init_web_page() -> Router {
    let serve_dir_from_public = ServeDir::new("public");
    Router::new()
    .route("/restart", post(restart))
    .nest_service("/", serve_dir_from_public)
    .layer(CorsLayer::permissive())
}


async fn restart(
    Json(payload): Json<Mensaje>
) -> (StatusCode, Json<Mensaje>){

    let max_threads = 4; 
    let password_worker = PasswordWorker::new_bcrypt(max_threads).expect("Falló el Password Worker");
    //let cost = 12; // bcrypt cost value
    //let hashed_password = password_worker.hash(password, BcryptConfig { cost }).await;
    let hashed_password = "$2b$12$U99GgkGqvCcyTQOzJDDMGuu0Ck/275EzCrnRCND33Wsk5ZifJhyRO";
    //println!("Hashed password: {:?}", hashed_password);
    let is_valid = password_worker.verify(&payload.msg, hashed_password).await;

    match is_valid {
        Ok(valid) => {
            if valid {
                println!("Contraseña válida.");
                let output = Command::new("restartZomboid.sh").output().expect("No pude ejecutar el comando.");
                println!("Mensaje stdout: {}", String::from_utf8(output.stdout).expect("Error al convertir stdout"));
                let ret = Mensaje {
                    msg: String::from("El servidor se está reiniciando.")
                };
                return (StatusCode::ACCEPTED, Json(ret));
            }else{
                println!("Contraseña incorrecta.");
                let ret = Mensaje {
                    msg: String::from("Contraseña incorrecta.")
                };
                return (StatusCode::UNAUTHORIZED, Json(ret));
            }
        },
        Err(e) => {
            println!("{:?}", e);
            let ret = Mensaje {
                msg: String::from("El admin la cagó en algo. Falla de servidor. Avísenle xD.")
            };
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(ret));
        },
    };
    
}

#[derive(Deserialize, Serialize, Debug)]
struct Mensaje {
    msg: String,
}

