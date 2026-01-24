use rocket::{http::{ContentType, Status}, response::{self, Responder}, Request, Response};
pub use rocket::request::{Outcome, FromRequest};
use super::*;
use crate::constants::*;
use jsonwebtoken::{decode as jwt_decode, DecodingKey, Validation};
use std::{convert::Infallible, fmt::Display, io::{Cursor, Write}};
impl HtmlFromString{
    pub const fn default(content: String) -> Self{
        HtmlFromString{
            content: content,
            content_type: ContentType::HTML
        }
    }
}

impl<'s> RespFromStr<'s>{
    pub const fn default(content: &'s str) -> Self{
        RespFromStr{
            content: content,
            content_type: ContentType::HTML
        }
    }
    pub const fn css(content: &'s str) -> Self{
        RespFromStr{
            content: content,
            content_type: ContentType::CSS
        }
    }
}


//Функціонал валідації JWT токенів
use rocket::http::uri::Origin;
#[rocket::async_trait]
impl<'r> FromRequest<'r> for JWTAuthenticated<'r, Origin<'r>>{
    type Error = Infallible;
    async fn from_request(req: &'r Request<'_>) -> Outcome<Self, Infallible>{
        match req.cookies().get("jwt"){
            Some(token) => {
                let mut validation = Validation::new(JWT_ALGORITHM);
                validation.leeway = JWT_LEEWAY;
                match jwt_decode::<JWTClaims>(&token.value(), &DecodingKey::from_secret(JWT_SECRET), &validation){
                    Ok(decoded_token) => {
                        match decoded_token.claims.role.as_ref(){
                            "Admin" => Outcome::Success(JWTAuthenticated::Admin),
                            "User" => Outcome::Success(JWTAuthenticated::User),
                            _ => Outcome::Forward(Status::Unauthorized)
                        }
                    }
                    Err(_) => {
                        let req_headers = req.headers();
                        let jwt_return_stuff = JWTLogStuff{
                            uri: req.uri(),
                            sec_ch_ua: req_headers.get_one("sec-ch-ua").get_or_insert("Undefined"),
                            platform: req_headers.get_one("sec-ch-ua-platform").get_or_insert("Undefined"),
                            error_reason: JWTFailReason::InvalidToken
                        };
                        Outcome::Success(JWTAuthenticated::Error(jwt_return_stuff))
                    }
                }
            },
            None => {
                let req_headers = req.headers();
                let jwt_return_stuff = JWTLogStuff{
                    uri: req.uri(),
                    sec_ch_ua: req_headers.get_one("sec-ch-ua").get_or_insert("Undefined"),
                    platform: req_headers.get_one("sec-ch-ua-platform").get_or_insert("Undefined"),
                    error_reason: JWTFailReason::ApsentToken
                };
                Outcome::Success(JWTAuthenticated::Error(jwt_return_stuff))
            }
        }
    }
}

impl JWTClaims{
    pub fn admin() -> Self{
        let time_now = Local::now();
        println!("{}",time_now);
        JWTClaims{
            role: "Admin".to_string(),
            exp: (time_now + JWT_LIFE_TIME).timestamp(),
            iat: time_now.timestamp()
        }
    }
    pub fn user() -> Self{
        let time_now = Local::now();
        println!("{}",time_now);
        JWTClaims{
            role: "User".to_string(),
            exp: (time_now + JWT_LIFE_TIME).timestamp(),
            iat: time_now.timestamp()
        }
    }
}

//Забезпечує роботу типа RespOrForwars
#[rocket::async_trait]
impl<'r, 's: 'r> Responder<'r, 's> for RespOrForward<'s>{
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'s>{
        match self {
            RespOrForward::HtmlFromStr(html_str) => {
                response::Result::Ok(Response::build()
                .status(Status::Ok)
                    .raw_header("content-type", "text/html; charset=utf-8")
                    .sized_body(html_str.len(), Cursor::new(html_str))
                    .finalize())
            },
            RespOrForward::HtmlFromString(html_string) => {
                response::Result::Ok(Response::build()
                .status(Status::Ok)
                    .raw_header("content-type", "text/html; charset=utf-8")
                    .sized_body(html_string.len(), Cursor::new(html_string))
                    .finalize())
            },
            RespOrForward::ForwardWith(status) => {
                response::Result::Err(status)
            }
        }
    }
}

impl PathParamsBuilder{
    pub fn new(base_path: String) -> PathParamsBuilder{
        PathParamsBuilder{
            path: base_path,
            querry_is_first: true
        }
    }
    pub fn add_parameter(&mut self, name: &'static str, value: &'static str){
        self.add_delimiter();
        self.path += name;
        self.path += "=";
        self.path += value;
        self.querry_is_first = false;
    }
    pub fn finalize(self) -> String{
        self.path
    }
    fn add_delimiter(&mut self){
        match self.querry_is_first{
            true => self.path += "?",
            false => self.path += "&"
        }
    }
}

impl<'s> Logger{
    pub fn new(file: File) -> Self{
        Logger{
            base_file: file
        }
    }
    pub fn log<T:Display>(&mut self, input: &T){
        _ =self.base_file.write_fmt(format_args!("{}\n",input))
    }
    pub fn flush(&mut self){
        _ =self.base_file.flush()
    }
}