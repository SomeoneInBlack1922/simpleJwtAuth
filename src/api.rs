use std::sync::{LockResult, RwLock};

use crate::{constants::*, my_regex::*, structs::*};
use minijinja::render;
use rocket::{form::Form, http::{Cookie, CookieJar, Status, uri::Origin}, response::Redirect, State};
use jsonwebtoken::{encode as jwt_encode, EncodingKey, Header};
#[get("/")]
//Головна сторінка
pub async fn internal(option_role: JWTAuthenticated<'_, Origin<'_>>) -> HtmlFromString{
    let level_name = match option_role{
        JWTAuthenticated::Admin => "Адміністратор",
        JWTAuthenticated::User => "Звичайний користувач",
        JWTAuthenticated::Error(_) => "Не зареєстрований"
    };
    let prepared_page = render!(INDEX_FILE, level => level_name);
    HtmlFromString{
        content: prepared_page,
        content_type: ContentType::HTML
    }
}

//Сторінка автентифікації
#[get("/login?<error>")]
pub fn login_page(error: bool) -> HtmlFromString{
    match error {
        true => HtmlFromString::default(render!(LOGIN_FILE, class => "oops", title => "Не вірні пошта чи пароль")),
        false => HtmlFromString::default(render!(LOGIN_FILE, title => "Введіть пошту та пароль"))
    }
}

//Ендпоінт для обробки форми надісланої з сторінки автентифікації
//Видає JWT токени в середині кукі
//Редіректить на головну сторінку якщо автентифіковано успішно або вертає на сторінку входу із банером про помилку
#[post("/authenticate", format = "form", data="<form>")]
pub fn authenticate(form: Form<AuthorizeForm>, cookies: &CookieJar) -> Redirect{
    match form.into_inner() {
        ADMIN_FORM => {
            match jwt_encode(&Header::default(), &JWTClaims::admin(), &EncodingKey::from_secret(&JWT_SECRET)){
                Ok(encoded_token) => {
                    cookies.add(default_cookie(("jwt", encoded_token)));
                },
                Err(_) => return Redirect::to("/login/?oops=true")
            }
        },
        REGULAR_USER_FORM => {
            match jwt_encode(&Header::default(), &JWTClaims::user(), &EncodingKey::from_secret(&JWT_SECRET)){
                Ok(encoded_token) => {
                    cookies.add(default_cookie(("jwt", encoded_token)));
                },
                Err(_) => return Redirect::to("/login/?oops=true")
            }
        },
        _ => {
            return Redirect::to("/login/?oops=true")
        }
    }
    Redirect::to("/")
}

//Видає статичний файл
//Я не використовую файл сервер наданий фреймворком бо я вбудував файли в середину бінарника. Бо захотів
//css окремим ендпоінтом бо я хотів налаштувати кешування браузером одного файла для всіх сторінок, але закинув цю ідею
#[get("/main.css", format="css")]
pub const fn main_css() -> RespFromStr<'static>{
    RespFromStr::css(MAIN_CSS_FILE)
}

//Сторінка доступна лише адміністракторам
#[get("/admin")]
pub async fn admin_page(role: JWTAuthenticated<'_, Origin<'_>>, logger: &State<RwLock<Logger>>) -> RespOrForward<'static>{
    match role{
        JWTAuthenticated::Admin => RespOrForward::HtmlFromStr(ADMIN_FILE),
        JWTAuthenticated::User => RespOrForward::ForwardWith(Status::Unauthorized),
        JWTAuthenticated::Error(log_stuff) => {
            jwt_log(log_stuff, logger).await;
            RespOrForward::ForwardWith(Status::Unauthorized)
        }
    }
}

//Сторінка доступна лише зареєстрованим користувачам
#[get("/authorized")]
pub async fn authorized_page(authorized: JWTAuthenticated<'_, Origin<'_>>, logger: &State<RwLock<Logger>>) -> RespOrForward<'static>{
    if let JWTAuthenticated::Error(log_stuff) = authorized{
        jwt_log(log_stuff, logger).await;
        RespOrForward::ForwardWith(Status::Unauthorized)
    }
    else {RespOrForward::HtmlFromStr(AUTHORIZED_FILE)}
}

//Ендпоінт щоб вийти із акаунта. Видаляє кукі з токеном.
#[get("/leve")]
pub fn leve(cookies: &CookieJar) -> Redirect{
    cookies.remove("jwt");
    Redirect::to("/")
}

//Сторінка із валідацією
#[get("/validate?<invalid_login>&<invalid_name>&<invalid_password>&<invalid_email>&<invalid_birthday>&<sucess>")]
pub fn validate_page(
        invalid_login: bool,
        invalid_name: bool,
        invalid_password: bool,
        invalid_email: bool,
        invalid_birthday: bool,
        sucess: bool
    ) -> RespOrForward<'static>{
        if sucess && !invalid_login && !invalid_name && !invalid_password && !invalid_email && !invalid_birthday {
            return RespOrForward::HtmlFromString(render!(
                VALIDATION_FILE,
                title => r#"<p class="cool">Ворма була введена успішно!</p>"#,
                login_text => r#"<p class="label">Логін</p>"#,
                name_text => r#"<p class="label">Ім'я</p>"#,
                password_text => r#"<p class="label">Пароль</p>"#,
                email_text => r#"<p class="label">Пошта</p>"#,
                birthday_text => r#"<p class="label">Дата народження</p>"#
            ))
        }
        else if !sucess {
            RespOrForward::HtmlFromString(
                render!(
                    VALIDATION_FILE,
                    title => match invalid_login || invalid_name || invalid_password || invalid_email || invalid_birthday {
                        true => r#"<p class="oops">Форма містила помилки</p>"#,
                        false => r#"<p>Заповніть форму</p>"#
                    },
                    login_text => {
                        match invalid_login {
                            true => r#"<p class="oops label">Логін не дійсний</p>"#,
                            false => r#"<p class="label">Логін</p>"#
                        }
                    },
                    name_text => {
                        match invalid_name {
                            true => r#"<p class="oops label">Ім'я не дійсне</p>"#,
                            false => r#"<p class="label">Ім'я</p>"#
                        }
                    },
                    password_text => {
                        match invalid_password{
                            true => r#"<p class="oops label">Пароль не дійсний</p>"#,
                            false => r#"<p class="label">Пароль</p>"#
                        }
                    },
                    email_text => {
                        match invalid_email{
                            true => r#"<p class="oops label">Пошта не дійсна</p>"#,
                            false => r#"<p class="label">Пошта</p>"#
                        }
                    },
                    birthday_text => {
                        match invalid_birthday{
                            true => r#"<p class="oops label">Дата народження не дійсна</p>"#,
                            false => r#"<p class="label">Дата народження</p>"#
                        }
                    }
                )
            )
        }
        else {
            RespOrForward::ForwardWith(Status::UnprocessableEntity)
        }
}

//Ендпоінт що валідує данні відправлені зі сторінки валідації.
//Перенаправляє назад на сторінку валідації і використовує uri парметри щоб підсвітити результат
#[post("/validate", data = "<input>")]
pub fn validate(input: Form<ValidateForm>, my_regex: &State<MyRegex>) -> Redirect{
    use chrono::{NaiveDate, Local};
    let mut validation_ok = true;
    let mut redirect_path = PathParamsBuilder::new("/validate".to_string());
    if !my_regex.validate_login(input.login) {redirect_path.add_parameter("invalid_login", "true"); validation_ok = false;}
    if !my_regex.validate_name(input.name) {redirect_path.add_parameter("invalid_name", "true"); validation_ok = false;}
    if !my_regex.validate_password(input.password) {redirect_path.add_parameter("invalid_password", "true"); validation_ok = false;}
    if !my_regex.validate_email(input.email) {redirect_path.add_parameter("invalid_email", "true"); validation_ok = false;}
    match NaiveDate::parse_from_str(input.birthday, "%Y-%m-%d") {
        Ok(parsed_date) => {
            if parsed_date > Local::now().naive_local().date(){
                redirect_path.add_parameter("invalid_birthday", "true");
                validation_ok = false;
            }
        },
        Err(_) => {
            redirect_path.add_parameter("invalid_birthday", "true");
            validation_ok = false;
        }
    };
    if validation_ok {
        redirect_path.add_parameter("sucess", "true");
    }
    Redirect::to(redirect_path.finalize())
}

//Створює всі кукі. Всі параметри крім базового шляха можна налаштувати із констант
use chrono::Local;
fn default_cookie<'r, T: Into<Cookie<'r>>>(input: T) -> Cookie<'r>{
    return Cookie::from(Cookie::build(input).http_only(COOKIE_HTTP_ONLY).path("/").max_age(COOKIE_LIFE_TIME).same_site(COOKIE_SAME_SITE))
}

//Виводить данні в лог файл
//Через архітектуру фреймворка яка не передбачає можливість логування і заважає використовувати бібліотеку log я був змушений робити це вручну
async fn jwt_log(log_stuff: JWTLogStuff<'_, Origin<'_>>, logger: &RwLock<Logger>){
    if let LockResult::Ok(mut lock) = logger.write(){
        lock.log(
            &format!(
                "{}; {}_JWT path:{}; sec-ch-ua:{}; platform:{}",
                Local::now().format("%d.%m.%Y %H:%M:%S"),
                match log_stuff.error_reason {
                    JWTFailReason::ApsentToken => "apsent",
                    JWTFailReason::InvalidToken => "invalid"
                },
                log_stuff.uri,
                log_stuff.sec_ch_ua,
                log_stuff.platform
            )
        );
        lock.flush();
    }
}