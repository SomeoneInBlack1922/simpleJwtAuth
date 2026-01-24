use regex::Regex;
pub struct MyRegex{
    pub login: Regex,
    pub name: Regex,
    pub password_set: PasswordRegexSet,
    pub email_regex: Regex
}
pub struct PasswordRegexSet {
    pub has_whitespace: Regex,
    pub has_special_symbol: Regex,
    pub has_number: Regex,
    pub has_capital_letter: Regex,
    pub has_lowercase_letter: Regex
}
impl MyRegex{
    pub fn validate_login(&self, input: &'_ str) -> bool{
        self.login.is_match(input)
    }
    pub fn validate_name(&self, input: &'_ str) -> bool{
        self.name.is_match(input)
    }
    pub fn validate_password(&self, input: &'_ str) -> bool{
        let regex_samples = &self.password_set;
        return (input.len() >= 8 && input.len() <= 50) && 
        !regex_samples.has_whitespace.is_match(input) &&
        regex_samples.has_special_symbol.is_match(input) &&
        regex_samples.has_number.is_match(input) &&
        regex_samples.has_capital_letter.is_match(input) &&
        regex_samples.has_lowercase_letter.is_match(input)
    }
    pub fn validate_email(&self, input: &'_ str) -> bool {
        self.email_regex.is_match(input)
    }
}