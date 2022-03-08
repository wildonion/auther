






use crate::contexts as ctx;
use crate::schemas;
use crate::constants::*;
use crate::utils;
use futures::{executor::block_on, TryFutureExt, TryStreamExt}; //-- based on orphan rule TryStreamExt trait is required to use try_next() method on the future object which is solved by .await - try_next() is used on futures stream or chunks to get the next future IO stream
use bytes::Buf; //-- based on orphan rule it'll be needed to call the reader() method on the whole_body buffer
use mongodb::bson::doc;
use actix_web::{Error, HttpRequest, HttpResponse, Result, get, post, web};










#[post("/check-token")]
async fn check_token(req: HttpRequest) -> Result<HttpResponse, Error>{
    
    match middlewares::auth::pass(req).await{
        Ok(token_data) => { //-- claims contains _id, username, iat and exp
            let user_id = token_data.claims._id; //-- this is the mongodb ObjectId as BSON
            let username = token_data.claims.username;
            let response_body = ctx::app::Response::<ctx::app::Nill>{
                data: Some(ctx::app::Nill(&[])), //-- data is an empty &[u8] array
                message: ACCESS_GRANTED,
                status: 200,
            };
            Ok(
                HttpResponse::Unauthorized().json(
                    response_body
                ).into_body()
            )
        },
        Err(e) => {
            let response_body = ctx::app::Response::<ctx::app::Nill>{
                data: Some(ctx::app::Nill(&[])), //-- data is an empty &[u8] array
                message: &e.to_string(), //-- take a reference to the string error
                status: 401,
            };
            Ok(
                HttpResponse::Unauthorized().json(
                    response_body
                ).into_body()
            )
        }
    }
    
}

#[get("/login")]
async fn login(req: HttpRequest, user_info: web::Json<schemas::auth::LoginRequest>) -> Result<HttpResponse, Error>{

    let conn = utils::db::connection().await;
    let app_storage = match conn.as_ref().unwrap().db.as_ref().unwrap().mode{ //-- here as_ref() method convert &Option<T> to Option<&T>
        ctx::app::Mode::On => conn.as_ref().as_ref().unwrap().db.as_ref().unwrap().instance.as_ref(), //-- return the db if it wasn't detached - instance.as_ref() will return the Option<&Client>
        ctx::app::Mode::Off => None, //-- no db is available cause it's off
    };

    let user_info = user_info.into_inner(); //-- into_inner() will deconstruct to an inner value and return T 
    let users = app_storage.unwrap().database("bitrader").collection::<schemas::auth::UserInfo>("users"); //-- selecting users collection to fetch all user infos into the UserInfo struct
    match users.find_one(doc!{"username": user_info.username.clone()}, None).unwrap(){ //-- finding user based on username
        Some(user_doc) => { //-- deserializing BSON into the UserInfo struct
            match schemas::auth::LoginRequest::verify_pwd(user_doc.pwd.clone(), user_info.pwd.clone()).await{
                Ok(_) => { // if we're here means hash and raw are match together and we had a successful login
                    let (now, exp) = utils::jwt::gen_times().await;
                    let jwt_payload = utils::jwt::Claims{_id: user_doc._id.clone(), username: user_doc.username.clone(), iat: now, exp};
                    match utils::jwt::construct(jwt_payload).await{ //-- constructing jwt on login
                        Ok(token) => {
                            let user_response = schemas::auth::LoginResponse{
                                _id: user_doc._id,
                                access_token: token,
                                username: user_doc.username,
                                phone: user_doc.phone,
                                role: user_doc.role,
                                status: user_doc.status,
                                created_at: user_doc.created_at,
                            };
                            let response_body = ctx::app::Response::<schemas::auth::LoginResponse>{ //-- we have to specify a generic type for data field in Response struct which in our case is LoginResponse struct
                                data: Some(user_response), //-- deserialize_from_json_into_struct is of type UserInfo struct 
                                message: ACCESS_GRANTED,
                                status: 200,
                            };
                            Ok(
                                HttpResponse::Ok().json(
                                    response_body
                                ).into_body()
                            )
                        },
                        Err(e) => {
                            let response_body = ctx::app::Response::<ctx::app::Nill>{
                                data: Some(ctx::app::Nill(&[])), //-- data is an empty &[u8] array
                                message: &e.to_string(), //-- take a reference to the string error
                                status: 500,
                            };
                            Ok(
                                HttpResponse::InternalServerError().json(
                                    response_body
                                ).into_body()
                            )
                        },
                    }
                },
                Err(e) => {
                    let response_body = ctx::app::Response::<ctx::app::Nill>{
                        data: Some(ctx::app::Nill(&[])), //-- data is an empty &[u8] array
                        message: &e.to_string(), //-- take a reference to the string error
                        status: 500,
                    };
                    Ok(
                        HttpResponse::InternalServerError().json(
                            response_body
                        ).into_body()
                    )
                },
            }
        }, 
        None => { //-- means we didn't find any document related to this username and we have to tell the user do a signup
            let response_body = ctx::app::Response::<ctx::app::Nill>{ //-- we have to specify a generic type for data field in Response struct which in our case is Nill struct
                data: Some(ctx::app::Nill(&[])), //-- data is an empty &[u8] array
                message: DO_SIGNUP, //-- document not found in database and the user must do a signup
                status: 404,
            };
            Ok(
                HttpResponse::NotFound().json(
                    response_body
                ).into_body()
            )
        }
    }

}


#[post("/signup")]
async fn signup(req: HttpRequest, user_info: web::Json<schemas::auth::RegisterRequest>) -> Result<HttpResponse, Error>{
    
    let conn = utils::db::connection().await;
    let app_storage = match conn.as_ref().unwrap().db.as_ref().unwrap().mode{ //-- here as_ref() method convert &Option<T> to Option<&T>
        ctx::app::Mode::On => conn.as_ref().as_ref().unwrap().db.as_ref().unwrap().instance.as_ref(), //-- return the db if it wasn't detached - instance.as_ref() will return the Option<&Client>
        ctx::app::Mode::Off => None, //-- no db is available cause it's off
    };

    let user_info = user_info.into_inner(); //-- into_inner() will deconstruct to an inner value and return T 
    let users = app_storage.unwrap().database("bitrader").collection::<schemas::auth::RegisterResponse>("users");
    match users.find_one(doc!{"username": user_info.clone().username}, None).unwrap(){ //-- finding user based on username
        Some(user_doc) => { //-- if we find a user with this username we have to tell the user do a login 
            let response_body = ctx::app::Response::<ctx::app::Nill>{ //-- we have to specify a generic type for data field in Response struct which in our case is Nill struct
                data: Some(ctx::app::Nill(&[])),
                message: DO_LOGIN, //-- please login message
                status: 302,
            };
            Ok(
                HttpResponse::Found().json(
                    response_body
                ).into_body()
            )       
        }, 
        None => { //-- no document found with this username thus we must insert a new one into the databse
            let users = app_storage.unwrap().database("bitrader").collection::<schemas::auth::RegisterRequest>("users");
            match schemas::auth::RegisterRequest::hash_pwd(user_info.pwd.clone()).await{
                Ok(hash) => {
                    let user_doc = schemas::auth::RegisterRequest{
                        username: user_info.username.clone(), //-- cloning username in order not to move although we can't move it cause Copy trait is not implemented for String and in order to move it we have to take a reference to the location of the String inside the heap thus the username filed type must be defined as &String
                        phone: user_info.phone.clone(), //-- cloning phone in order not to move although we can't move it cause Copy trait is not implemented for String and in order to move it we have to take a reference to the location of the String inside the heap thus the phone filed type must be defined as &String
                        pwd: hash,
                        role: user_info.role.clone(), //-- cloning role in order not to move although we can't move it cause Copy trait is not implemented for String and in order to move it we have to take a reference to the location of the String inside the heap thus the role filed type must be defined as &String
                        status: user_info.status,
                        created_at: Some(chrono::Local::now().naive_local()),
                    };
                    match users.insert_one(user_doc, None){ //-- serializing the user doc which is of type RegisterRequest into the BSON to insert into the mongodb
                        Ok(insert_result) => {
                            let response_body = ctx::app::Response::<mongodb::bson::Bson>{ //-- we have to specify a generic type for data field in Response struct which in our case is Bson struct
                                data: Some(insert_result.inserted_id),
                                message: REGISTERED,
                                status: 200,
                            };
                            Ok(
                                HttpResponse::Ok().json(
                                    response_body
                                ).into_body()
                            )
                        },
                        Err(e) => {
                            let response_body = ctx::app::Response::<ctx::app::Nill>{
                                data: Some(ctx::app::Nill(&[])), //-- data is an empty &[u8] array
                                message: &e.to_string(), //-- take a reference to the string error
                                status: 406,
                            };
                            Ok(
                                HttpResponse::NotAcceptable().json(
                                    response_body
                                ).into_body()
                            )
                        }
                    }
                },
                Err(e) => {
                    let response_body = ctx::app::Response::<ctx::app::Nill>{
                        data: Some(ctx::app::Nill(&[])), //-- data is an empty &[u8] array
                        message: &e.to_string(), //-- take a reference to the string error
                        status: 500,
                    };
                    Ok(
                        HttpResponse::InternalServerError().json(
                            response_body
                        ).into_body()
                    )
                }
            }
        }
    }
    
}








pub fn register(config: &mut web::ServiceConfig){
    config.service(check_token);
    config.service(login);
    config.service(signup);
}
