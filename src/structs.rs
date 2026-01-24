use std::{fmt::Display, fs::File};

use chrono::Local;
pub use rocket::http::ContentType;
use rocket::http::Status;
use serde::{Serialize, Deserialize};
mod impls;

//200 відповідь із стрінги
#[derive(Responder)]
pub struct HtmlFromString{
    pub content: String,
    pub content_type: ContentType
}

//200 відповідь із стр
#[derive(Responder)]
pub struct RespFromStr<'s>{
    pub content: &'s str,
    pub content_type: ContentType
}

//3 варіанти повернути значення з ендпоінта
pub enum RespOrForward<'r>{
    HtmlFromString(String),
    HtmlFromStr(&'r str),
    ForwardWith(Status)
}

#[derive(PartialEq)]
#[derive(FromForm)]
pub struct AuthorizeForm<'r>{
    pub email: &'r str,
    pub password: &'r str
}

#[derive(FromForm)]
pub struct ValidateForm<'r>{
    pub login:  &'r str,
    pub name: &'r str,
    pub password: &'r str,
    pub email: &'r str,
    pub birthday: &'r str
}

pub struct Logger{
    base_file: File
}


pub enum JWTAuthenticated<'a, A: Display>{
    Admin,
    User,
    Error(JWTLogStuff<'a, A>)
}

pub struct JWTLogStuff<'a, A: Display>{
    pub uri: &'a A,
    pub sec_ch_ua: &'a str,
    pub platform: &'a str,
    pub error_reason: JWTFailReason
}
#[derive(Debug)]
pub enum JWTFailReason{
    InvalidToken,
    ApsentToken
}

#[derive(Serialize, Deserialize)]
pub struct JWTClaims{
    role: String,
    exp: i64,
    iat: i64
}

//Швидко накиданий білдер щоб додавати параметр запита
pub struct PathParamsBuilder{
    path: String,
    querry_is_first: bool
}