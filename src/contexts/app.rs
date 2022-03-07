









use futures::Future;
use mongodb::sync::Client; //-- we're using sync mongodb cause mongodb requires tokio to be in Cargo.toml and there is a confliction with the actix tokio
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use actix_web::{Error, HttpRequest, HttpResponse, Result};








#[derive(Debug)]
pub struct Api{
    pub name: String,
    pub req: Option<HttpRequest>,
    pub res: Option<HttpResponse>,
}


impl Api{

    pub async fn new(request: Option<HttpRequest>, response: Option<HttpResponse>) -> Self{
        Api{
            name: String::from(""),
            req: request,
            res: response,
        }
    }
    
    pub async fn post<F, C>(mut self, endpoint: &str, mut cb: F) -> Result<HttpResponse, Error> //-- defining self (an instance of the object) as mutable cause we want to assign the name of the api
                        where F: FnMut(HttpRequest, HttpResponse) -> C, //-- capturing by &mut T
                        C: Future<Output=Result<HttpResponse, Error>> + Send, //-- C is a future object which will be returned by the closure and has bounded to Send to move across threads
    {
        self.name = endpoint.to_string(); //-- setting the api name to the current endpoint
        let req = self.req.unwrap();
        let res = self.res.unwrap();
        let cb_res = cb(req, res).await.unwrap(); //-- this would be of type either hyper::Response<Body> or hyper::Error
        Ok(cb_res)
    }
    
    pub async fn get<F, C>(mut self, endpoint: &str, mut cb: F) -> Result<HttpResponse, Error> //-- defining self (an instance of the object) as mutable cause we want to assign the name of the api
                        where F: FnMut(HttpRequest, HttpResponse) -> C, //-- capturing by &mut T
                        C: Future<Output=Result<HttpResponse, Error>> + Send, //-- C is a future object which will be returned by the closure and has bounded to Send to move across threads
    {
        self.name = endpoint.to_string(); //-- setting the api name to the current endpoint
        let req = self.req.unwrap();
        let res = self.res.unwrap();
        let cb_res = cb(req, res).await.unwrap(); //-- this would be of type either hyper::Response<Body> or hyper::Error
        Ok(cb_res)
    }
}




#[derive(Clone, Debug)] //-- can't bound Copy trait cause engine and url are String which are heap data structure 
pub struct Db{
    pub mode: Mode,
    pub engine: Option<String>,
    pub url: Option<String>,
    pub instance: Option<Client>,
}

impl Default for Db{
    fn default()-> Db {
        todo!()
    }
}

impl Db{
    
    pub async fn new() -> Result<Db, Box<dyn std::error::Error>>{
        Ok(
            Db{ //-- building an instance with generic type C which is the type of the db client instance
                mode: super::app::Mode::On, //-- 1 means is on 
                engine: None, 
                url: None,
                instance: None,
            }
        )
    }
    
    pub async fn GetMongoDbInstance(&self) -> Client{ //-- it'll return an instance of the mongodb client
        Client::with_uri_str(self.url.as_ref().unwrap()).unwrap() //-- building mongodb client instance
    }

}




#[derive(Clone, Debug)]
pub struct Storage{
    pub id: Uuid,
    pub db: Option<Db>, //-- we could have no db at all
}



#[derive(Copy, Clone, Debug)]
pub enum Mode{
    On,
    Off,
}



#[derive(Serialize, Deserialize, Debug)]
pub struct Response<'m, T>{
    pub data: Option<T>,
    pub message: &'m str,
    pub status: u32,
}



#[derive(Serialize, Deserialize)]
pub struct Nill<'n>(pub &'n [u8]); //-- this will be used for empty data inside the data field of the Response struct - 'n is the lifetime of the &[u8] type cause every pointer needs a lifetime in order not to point to an empty location inside the memory

