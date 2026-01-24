use jsonwebtoken::Algorithm;
use crate::structs::AuthorizeForm;
use chrono::Duration;
//Статичні файли
//Вони завантажуються як текст у ці константи на етапі компіляції, тобто зберігаються у самому бінарнику
//Я знаю про rust-embed, але файли які він видає не статичні, наприклад я зміг зробити ендпоінт що видає css константним бо ці файли статичні
//Плюс я не впевнений чи будуть його функції оптимізовані до такої ж швидкості читання як із цими константами
pub const INDEX_FILE: &'static str = include_str!("../static/index.html");
pub const LOGIN_FILE: &'static str = include_str!("../static/login.html");
pub const UNAUTHORIZED_FILE: &'static str = include_str!("../static/unauthorized.html");
pub const UNPROCESSABLE_FILE: &'static str = include_str!("../static/unprocessable.html");
pub const ADMIN_FILE: &'static str = include_str!("../static/admin.html");
pub const MAIN_CSS_FILE: &'static str = include_str!("../static/main.css");
pub const VALIDATION_FILE: &'static str = include_str!("../static/validation.html");
pub const AUTHORIZED_FILE: &'static str = include_str!("../static/authorized.html");

//Трафорети для адміністратора та користувача для сторінки login.html
pub const REGULAR_USER_FORM: AuthorizeForm = AuthorizeForm {email: "user@host", password: "UserPassword"};
pub const ADMIN_FORM: AuthorizeForm = AuthorizeForm {email: "admin@host", password: "AdminPassword"};

//Налаштування JWT
pub const JWT_ALGORITHM: Algorithm = Algorithm::HS256;
pub const JWT_SECRET: &'static [u8] = include_bytes!("JWT_key.secret");
pub const JWT_LIFE_TIME: Duration = Duration::minutes(2);
pub const JWT_LEEWAY: u64 = 0; //Скільки секунд після спливання терміну токена його ще можна використати. Яке на мене це маячня, тому 0

//Налаштування кукі
// pub const COOKIE_SECRET: &'static str = include_str!("cookie_key.secret"); //Цей секретний ключ використовується фреймовком для шифрування вмісту кукі полів, тобто JWT токен лежить у кукі зашифрованим
pub const COOKIE_LIFE_TIME: rocket::time::Duration = rocket::time::Duration::minutes(2);
pub const COOKIE_SAME_SITE: cookie::SameSite = cookie::SameSite::Strict;
pub const COOKIE_HTTP_ONLY: bool = true;