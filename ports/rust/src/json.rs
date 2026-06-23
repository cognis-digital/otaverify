//! Minimal JSON parser + canonical (sorted-key, compact) encoder. Zero deps.
//! Enough to parse OTA package documents and reproduce the Python signing basis.

use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn get(&self, k: &str) -> Option<&Json> {
        if let Json::Obj(m) = self {
            m.get(k)
        } else {
            None
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Json::Str(s) = self {
            Some(s)
        } else {
            None
        }
    }
    pub fn as_int(&self) -> Option<i64> {
        if let Json::Num(n) = self {
            if n.fract() == 0.0 {
                return Some(*n as i64);
            }
        }
        None
    }
    pub fn as_arr(&self) -> Option<&Vec<Json>> {
        if let Json::Arr(a) = self {
            Some(a)
        } else {
            None
        }
    }
    pub fn as_obj(&self) -> Option<&BTreeMap<String, Json>> {
        if let Json::Obj(m) = self {
            Some(m)
        } else {
            None
        }
    }

    /// Canonical encoding: BTreeMap already orders keys; numbers print as
    /// integers when integral (matches Python's json for our inputs).
    pub fn canonical(&self) -> String {
        match self {
            Json::Null => "null".into(),
            Json::Bool(b) => b.to_string(),
            Json::Num(n) => {
                if n.fract() == 0.0 {
                    format!("{}", *n as i64)
                } else {
                    format!("{}", n)
                }
            }
            Json::Str(s) => encode_str(s),
            Json::Arr(a) => {
                let parts: Vec<String> = a.iter().map(|v| v.canonical()).collect();
                format!("[{}]", parts.join(","))
            }
            Json::Obj(m) => {
                let parts: Vec<String> = m
                    .iter()
                    .map(|(k, v)| format!("{}:{}", encode_str(k), v.canonical()))
                    .collect();
                format!("{{{}}}", parts.join(","))
            }
        }
    }
}

fn encode_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn parse(s: &str) -> Result<Json, String> {
    let chars: Vec<char> = s.chars().collect();
    let mut p = Parser { c: chars, i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    Ok(v)
}

struct Parser {
    c: Vec<char>,
    i: usize,
}

impl Parser {
    fn ws(&mut self) {
        while self.i < self.c.len() && self.c[self.i].is_whitespace() {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<char> {
        self.c.get(self.i).copied()
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.peek() {
            Some('{') => self.obj(),
            Some('[') => self.arr(),
            Some('"') => Ok(Json::Str(self.string()?)),
            Some('t') | Some('f') => self.boolean(),
            Some('n') => {
                self.i += 4;
                Ok(Json::Null)
            }
            Some(_) => self.number(),
            None => Err("unexpected eof".into()),
        }
    }
    fn obj(&mut self) -> Result<Json, String> {
        let mut m = BTreeMap::new();
        self.i += 1; // {
        self.ws();
        if self.peek() == Some('}') {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(':') {
                return Err("expected :".into());
            }
            self.i += 1;
            let v = self.value()?;
            m.insert(k, v);
            self.ws();
            match self.peek() {
                Some(',') => {
                    self.i += 1;
                }
                Some('}') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected , or }".into()),
            }
        }
        Ok(Json::Obj(m))
    }
    fn arr(&mut self) -> Result<Json, String> {
        let mut a = Vec::new();
        self.i += 1; // [
        self.ws();
        if self.peek() == Some(']') {
            self.i += 1;
            return Ok(Json::Arr(a));
        }
        loop {
            let v = self.value()?;
            a.push(v);
            self.ws();
            match self.peek() {
                Some(',') => {
                    self.i += 1;
                }
                Some(']') => {
                    self.i += 1;
                    break;
                }
                _ => return Err("expected , or ]".into()),
            }
        }
        Ok(Json::Arr(a))
    }
    fn string(&mut self) -> Result<String, String> {
        if self.peek() != Some('"') {
            return Err("expected string".into());
        }
        self.i += 1;
        let mut s = String::new();
        while let Some(ch) = self.peek() {
            self.i += 1;
            match ch {
                '"' => return Ok(s),
                '\\' => {
                    let e = self.peek().ok_or("bad escape")?;
                    self.i += 1;
                    match e {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        '/' => s.push('/'),
                        'n' => s.push('\n'),
                        'r' => s.push('\r'),
                        't' => s.push('\t'),
                        'b' => s.push('\u{0008}'),
                        'f' => s.push('\u{000C}'),
                        'u' => {
                            let hex: String = self.c[self.i..self.i + 4].iter().collect();
                            self.i += 4;
                            let n = u32::from_str_radix(&hex, 16).map_err(|_| "bad \\u")?;
                            if let Some(c) = char::from_u32(n) {
                                s.push(c);
                            }
                        }
                        _ => return Err("bad escape".into()),
                    }
                }
                _ => s.push(ch),
            }
        }
        Err("unterminated string".into())
    }
    fn boolean(&mut self) -> Result<Json, String> {
        if self.c[self.i] == 't' {
            self.i += 4;
            Ok(Json::Bool(true))
        } else {
            self.i += 5;
            Ok(Json::Bool(false))
        }
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        while let Some(ch) = self.peek() {
            if ch.is_ascii_digit() || ch == '-' || ch == '+' || ch == '.' || ch == 'e' || ch == 'E' {
                self.i += 1;
            } else {
                break;
            }
        }
        let txt: String = self.c[start..self.i].iter().collect();
        txt.parse::<f64>().map(Json::Num).map_err(|_| "bad number".into())
    }
}
