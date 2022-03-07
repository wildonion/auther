




/*



Coded by



 █     █░ ██▓ ██▓    ▓█████▄  ▒█████   ███▄    █  ██▓ ▒█████   ███▄    █ 
▓█░ █ ░█░▓██▒▓██▒    ▒██▀ ██▌▒██▒  ██▒ ██ ▀█   █ ▓██▒▒██▒  ██▒ ██ ▀█   █ 
▒█░ █ ░█ ▒██▒▒██░    ░██   █▌▒██░  ██▒▓██  ▀█ ██▒▒██▒▒██░  ██▒▓██  ▀█ ██▒
░█░ █ ░█ ░██░▒██░    ░▓█▄   ▌▒██   ██░▓██▒  ▐▌██▒░██░▒██   ██░▓██▒  ▐▌██▒
░░██▒██▓ ░██░░██████▒░▒████▓ ░ ████▓▒░▒██░   ▓██░░██░░ ████▓▒░▒██░   ▓██░
░ ▓░▒ ▒  ░▓  ░ ▒░▓  ░ ▒▒▓  ▒ ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ 
  ▒ ░ ░   ▒ ░░ ░ ▒  ░ ░ ▒  ▒   ░ ▒ ▒░ ░ ░░   ░ ▒░ ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░
  ░   ░   ▒ ░  ░ ░    ░ ░  ░ ░ ░ ░ ▒     ░   ░ ░  ▒ ░░ ░ ░ ▒     ░   ░ ░ 
    ░     ░      ░  ░   ░        ░ ░           ░  ░      ░ ░           ░ 
                      ░                                                  



*/




mod middlewares;
mod utils;
mod constants;
mod contexts;
mod schemas;
mod apis;






use std::net::SocketAddr;
use dotenv::dotenv;
use std::env;
use actix_web::{web, App, HttpServer, middleware::Logger};











// NOTE - Error, Send and Sync are traits which must be bounded to a type, since we don't know the type in compile time (will be specified at runtime) we must put these trait inside a Box with the dyn keword behind them cause we don't know how much size they will take space inside the memory  


#[actix_web::main]
async fn main() -> std::io::Result<()>{ 
    
    








    // -------------------------------- environment variables setup
    //
    // ---------------------------------------------------------------------
    env::set_var("RUST_LOG", "actix_web=debug,actix_server=info");
    pretty_env_logger::init();
    dotenv().expect("⚠️ .env file not found");
    let io_buffer_size = env::var("IO_BUFFER_SIZE").expect("⚠️ no io buffer size variable set").parse::<u32>().unwrap() as usize; //-- usize is the minimum size in os which is 32 bits
    let environment = env::var("ENVIRONMENT").expect("⚠️ no environment variable set");
    let host = env::var("HOST").expect("⚠️ no host variable set");
    let port = env::var("BITRADER_AUTH_PORT").expect("⚠️ no port variable set for bitrader service");
    let server_addr = format!("{}:{}", host, port).as_str().parse::<SocketAddr>().unwrap(); //-- converting the host and port String into the as_str() then parse it based on SocketAddr generic type



    
    

    





    // -------------------------------- setup and run the server
    //
    // ---------------------------------------------------------------------
    HttpServer::new(move || {
        App::new()
            .service(
                web::scope("/auth")
                            .configure(apis::auth::register)
            )
            .wrap(Logger::default())
    })
    .bind(server_addr).unwrap()
    .run()
    .await











}
