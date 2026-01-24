#[macro_use] extern crate rocket;
use std::sync::RwLock;
use structs::Logger;
//Містить ендпоінти
mod api;
//Допоміжні типи і імплементації рис які я написав для своєї зручності та для JWT токенів
mod structs;
mod constants;
//Файл зі структурами вже великий, розбив це сюди
mod my_regex;
//Відповіді для ситуацій коли треба відправити клієнту не код 200
//По суті теж ендпоінти але викликаються лише іншими ендпоінтами
mod catchers;

use crate::{api::*, catchers::*};
use my_regex::*;
use regex::Regex;
use std::fs::File;

#[launch]
fn rocket() -> _ {
    //Визначення реджексів для використання на сторінц валідації
    let my_regex =  MyRegex{
        login: Regex::new(r#"([a-zA-Z_\d]){5,30}"#).unwrap(),
        name: Regex::new(r#"([a-zA-Z]){5,30}"#).unwrap(),
        //Імплементація реджекса у расті не має однієї фічі чекрез що не можна робити щось таке складне одним реджексом
        //І мені було занадто лінь дослідити це питання нормально
        password_set: PasswordRegexSet{
            has_whitespace: Regex::new(r"\s").unwrap(),
            has_special_symbol: Regex::new(r#"[()!#${}_\-+]"#).unwrap(),
            has_number: Regex::new(r"\d").unwrap(),
            has_capital_letter: Regex::new(r"[A-Z]").unwrap(),
            has_lowercase_letter: Regex::new(r"[a-z]").unwrap()
        },
        email_regex: Regex::new(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$").unwrap()
    };
    //Створення файла для логування
    let log_file = File::create("auth.log").unwrap();
    let logger = Logger::new(log_file);
    //Завантажити ключ для шифрування і дешифрування кукі з фійлу
    //Я вирішив не надсилати проект що шифрує кукі але ключ вже хай буде щоб ви розуміли що я це імплементував
    // let rocket = rocket::custom(
    //     rocket::Config::figment().merge(("global.secret_key", COOKIE_SECRET))
    // );
    //Запуск ендпоінтів
    rocket::build()
        .mount("/", routes![
            internal,
            authenticate,
            login_page,
            admin_page,
            leve,
            main_css,
            validate_page,
            validate,
            authorized_page
        ])
        //Відповіді для ситуацій коли треба відправити клієнту не код 200
        //По суті теж ендпоінти але викликаються лише іншими ендпоінтами
        .register("/", catchers![
            unauthorized_catcher,
            unprocessable_catcher
        ])
        // Імплементація dependency injection цього фреймворка
        // Необхідна бо реджекси не можна оголосити глобальними константами
        .manage(my_regex)
        .manage(RwLock::new(logger))
}