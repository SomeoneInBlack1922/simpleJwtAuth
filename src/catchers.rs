use crate::constants::*;
use crate::structs::RespFromStr;
#[catch(401)]
pub const fn unauthorized_catcher() -> RespFromStr<'static>{
    RespFromStr::default(UNAUTHORIZED_FILE)
}
#[catch(422)]
pub const fn unprocessable_catcher() -> RespFromStr<'static>{
    RespFromStr::default(UNPROCESSABLE_FILE)
}