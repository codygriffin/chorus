#![forbid(unsafe_code)]

//! SQL parser, binder and executor for the documented Chorus MVP subset.
//! The implementation is intentionally deterministic and keeps parser types
//! private to this crate.

use chorus_codec::{ApplyResult, SchemaOperationV1, encode_composite, hash32};
use chorus_common::{ChorusError, Datum, Limits, OriginId, Result, SqlError, SqlType};
use chorus_storage::{
    Catalog, ColumnDescriptor, ColumnState, ObjectState, StateSnapshot, StateStore, TableDescriptor,
};
use chorus_txn::{CommitSequencer, Committer, Transaction, TransactionStatus};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct ResultColumn {
    pub name: String,
    pub data_type: SqlType,
    pub table_oid: u32,
    pub column_oid: u32,
}
#[derive(Clone, Debug)]
pub struct QueryResult {
    pub columns: Vec<ResultColumn>,
    pub rows: Vec<Vec<Datum>>,
    pub command_tag: String,
    pub affected_rows: u64,
    pub notices: Vec<String>,
}
impl QueryResult {
    pub fn command(tag: impl Into<String>, rows: u64) -> Self {
        Self {
            columns: Vec::new(),
            rows: Vec::new(),
            command_tag: tag.into(),
            affected_rows: rows,
            notices: Vec::new(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SessionSettings {
    pub application_name: String,
    pub search_path: String,
    pub client_encoding: String,
    pub timezone: String,
    pub datestyle: String,
    pub transaction_isolation: String,
    pub transaction_read_only: bool,
    pub statement_timeout_ms: u64,
    pub idle_in_transaction_session_timeout_ms: u64,
    pub standard_conforming_strings: bool,
    pub extra_float_digits: i32,
    pub bytea_output: String,
}
impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            application_name: String::new(),
            search_path: "public, pg_catalog".into(),
            client_encoding: "UTF8".into(),
            timezone: "UTC".into(),
            datestyle: "ISO, MDY".into(),
            transaction_isolation: "serializable".into(),
            transaction_read_only: false,
            statement_timeout_ms: 0,
            idle_in_transaction_session_timeout_ms: 15_000,
            standard_conforming_strings: true,
            extra_float_digits: 3,
            bytea_output: "hex".into(),
        }
    }
}

pub struct SqlEngine {
    store: Arc<dyn StateStore>,
    committer: Arc<dyn Committer>,
    limits: Limits,
}
impl SqlEngine {
    pub fn new(
        store: Arc<dyn StateStore>,
        committer: Arc<dyn Committer>,
        limits: Limits,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            committer,
            limits,
        })
    }
    pub fn session(self: &Arc<Self>) -> SqlSession {
        SqlSession {
            engine: Arc::clone(self),
            txn: None,
            failed: false,
            settings: SessionSettings::default(),
            prepared: HashMap::new(),
            sequencer: Arc::new(CommitSequencer::new(self.committer.origin())),
        }
    }
    pub fn store(&self) -> &Arc<dyn StateStore> {
        &self.store
    }
}

#[derive(Clone, Debug)]
enum Statement {
    Begin {
        read_only: bool,
    },
    Commit,
    Rollback,
    Set(String, String),
    Show(String),
    CreateTable {
        name: String,
        if_not_exists: bool,
        columns: Vec<ColumnSpec>,
        primary_key: Vec<String>,
    },
    DropTable {
        name: String,
        if_exists: bool,
    },
    AlterTable {
        table: String,
        op: AlterOp,
    },
    CreateIndex {
        name: String,
        table: String,
        unique: bool,
        if_not_exists: bool,
        columns: Vec<(String, bool)>,
    },
    DropIndex {
        name: String,
        if_exists: bool,
    },
    Select(Select),
    Insert(Insert),
    Update(Update),
    Delete(Delete),
    Prepare {
        name: String,
        sql: String,
    },
    Execute {
        name: String,
        params: Vec<Expr>,
    },
    Unsupported(String),
}
#[derive(Clone, Debug)]
struct ColumnSpec {
    name: String,
    ty: SqlType,
    nullable: bool,
    default: Option<Datum>,
}
#[derive(Clone, Debug)]
enum AlterOp {
    Add(ColumnSpec),
    Drop(String),
    RenameTable(String),
    RenameColumn(String, String),
}
#[derive(Clone, Debug)]
struct Select {
    projection: Vec<Expr>,
    from: Option<String>,
    selection: Option<Expr>,
    order: Vec<(Expr, bool)>,
    limit: Option<usize>,
    offset: usize,
    distinct: bool,
}
#[derive(Clone, Debug)]
struct Insert {
    table: String,
    columns: Vec<String>,
    values: Vec<Vec<Expr>>,
    returning: Vec<Expr>,
    conflict_nothing: bool,
}
#[derive(Clone, Debug)]
struct Update {
    table: String,
    assignments: Vec<(String, Expr)>,
    selection: Option<Expr>,
    returning: Vec<Expr>,
}
#[derive(Clone, Debug)]
struct Delete {
    table: String,
    selection: Option<Expr>,
    returning: Vec<Expr>,
}
#[derive(Clone, Debug)]
enum Expr {
    Literal(Datum),
    Param(usize),
    Column(String),
    Qualified(String, String),
    Star,
    Unary(Unary, Box<Expr>),
    Binary(Box<Expr>, BinOp, Box<Expr>),
    IsNull(Box<Expr>, bool),
    In(Box<Expr>, Vec<Expr>, bool),
    Between(Box<Expr>, Box<Expr>, Box<Expr>, bool),
    Like(Box<Expr>, Box<Expr>, bool),
    Func(String, Vec<Expr>),
    Case(Vec<(Expr, Expr)>, Box<Expr>),
    Cast(Box<Expr>, SqlType),
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Unary {
    Not,
    Neg,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BinOp {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Concat,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Tok {
    Word(String),
    Str(String),
    Num(String),
    Param(usize),
    Op(String),
    L,
    R,
    Comma,
    Dot,
    Semi,
    Star,
}

struct Lexer {
    chars: Vec<char>,
    p: usize,
}
impl Lexer {
    fn new(s: &str) -> Self {
        Self {
            chars: s.chars().collect(),
            p: 0,
        }
    }
    fn run(mut self) -> std::result::Result<Vec<Tok>, SqlError> {
        let mut out = Vec::new();
        while self.p < self.chars.len() {
            let c = self.chars[self.p];
            if c.is_whitespace() {
                self.p += 1;
                continue;
            }
            if c == '-' && self.chars.get(self.p + 1) == Some(&'-') {
                self.p += 2;
                while self.p < self.chars.len() && self.chars[self.p] != '\n' {
                    self.p += 1;
                }
                continue;
            }
            if c == '/' && self.chars.get(self.p + 1) == Some(&'*') {
                self.p += 2;
                while self.p + 1 < self.chars.len()
                    && !(self.chars[self.p] == '*' && self.chars[self.p + 1] == '/')
                {
                    self.p += 1;
                }
                self.p = (self.p + 2).min(self.chars.len());
                continue;
            }
            match c {
                '\'' => out.push(Tok::Str(self.string()?)),
                '"' => out.push(Tok::Word(self.quoted()?)),
                '$' => out.push(self.param()?),
                '0'..='9' => out.push(Tok::Num(self.number())),
                'A'..='Z' | 'a'..='z' | '_' => out.push(Tok::Word(self.word())),
                '(' => {
                    self.p += 1;
                    out.push(Tok::L)
                }
                ')' => {
                    self.p += 1;
                    out.push(Tok::R)
                }
                ',' => {
                    self.p += 1;
                    out.push(Tok::Comma)
                }
                '.' => {
                    self.p += 1;
                    out.push(Tok::Dot)
                }
                ';' => {
                    self.p += 1;
                    out.push(Tok::Semi)
                }
                '*' => {
                    self.p += 1;
                    out.push(Tok::Star)
                }
                '+' | '-' | '/' | '=' | '<' | '>' | '!' | '|' => out.push(Tok::Op(self.operator())),
                _ => {
                    return Err(SqlError::new(
                        "42601",
                        format!("unexpected character '{c}'"),
                    ));
                }
            }
        }
        Ok(out)
    }
    fn word(&mut self) -> String {
        let s = self.p;
        while self.p < self.chars.len()
            && (self.chars[self.p].is_ascii_alphanumeric() || self.chars[self.p] == '_')
        {
            self.p += 1;
        }
        self.chars[s..self.p]
            .iter()
            .collect::<String>()
            .to_ascii_lowercase()
    }
    fn quoted(&mut self) -> std::result::Result<String, SqlError> {
        self.p += 1;
        let mut s = String::new();
        while self.p < self.chars.len() {
            let c = self.chars[self.p];
            self.p += 1;
            if c == '"' {
                if self.chars.get(self.p) == Some(&'"') {
                    s.push('"');
                    self.p += 1;
                    continue;
                }
                return Ok(s);
            }
            s.push(c);
        }
        Err(SqlError::new("42601", "unterminated quoted identifier"))
    }
    fn string(&mut self) -> std::result::Result<String, SqlError> {
        self.p += 1;
        let mut s = String::new();
        while self.p < self.chars.len() {
            let c = self.chars[self.p];
            self.p += 1;
            if c == '\'' {
                if self.chars.get(self.p) == Some(&'\'') {
                    s.push('\'');
                    self.p += 1;
                    continue;
                }
                return Ok(s);
            }
            s.push(c);
        }
        Err(SqlError::new("42601", "unterminated string literal"))
    }
    fn number(&mut self) -> String {
        let s = self.p;
        let mut dot = false;
        while self.p < self.chars.len()
            && (self.chars[self.p].is_ascii_digit() || (!dot && self.chars[self.p] == '.'))
        {
            if self.chars[self.p] == '.' {
                dot = true;
            }
            self.p += 1;
        }
        self.chars[s..self.p].iter().collect()
    }
    fn param(&mut self) -> std::result::Result<Tok, SqlError> {
        self.p += 1;
        let mut n = 0;
        while self.p < self.chars.len() && self.chars[self.p].is_ascii_digit() {
            n = n * 10 + self.chars[self.p].to_digit(10).unwrap() as usize;
            self.p += 1;
        }
        if n == 0 {
            Err(SqlError::new("42601", "invalid parameter"))
        } else {
            Ok(Tok::Param(n))
        }
    }
    fn operator(&mut self) -> String {
        let s = self.p;
        self.p += 1;
        if self.p < self.chars.len()
            && matches!(
                (self.chars[s], self.chars[self.p]),
                ('<', '=') | ('>', '=') | ('<', '>') | ('!', '=') | ('|', '|')
            )
        {
            self.p += 1;
        }
        self.chars[s..self.p].iter().collect()
    }
}

struct Parser {
    t: Vec<Tok>,
    p: usize,
}
impl Parser {
    fn batch(sql: &str) -> std::result::Result<Vec<Statement>, SqlError> {
        let t = Lexer::new(sql).run()?;
        let mut out = Vec::new();
        let mut start = 0;
        for i in 0..=t.len() {
            if i == t.len() || matches!(t[i], Tok::Semi) {
                if start < i {
                    out.push(
                        Self {
                            t: t[start..i].to_vec(),
                            p: 0,
                        }
                        .statement()?,
                    );
                }
                start = i + 1;
            }
        }
        Ok(out)
    }
    fn statement(&mut self) -> std::result::Result<Statement, SqlError> {
        let w = self.take_word()?;
        match w.as_str() {
            "begin" | "start" => {
                if w == "start" {
                    self.word("transaction")?;
                }
                let read_only = self.words(&["read", "only"]);
                Ok(Statement::Begin { read_only })
            }
            "commit" | "end" => Ok(Statement::Commit),
            "rollback" | "abort" => Ok(Statement::Rollback),
            "set" => self.set_stmt(),
            "show" => Ok(Statement::Show(self.take_word()?)),
            "create" => self.create_stmt(),
            "drop" => self.drop_stmt(),
            "alter" => self.alter_stmt(),
            "select" => self.select_stmt(false),
            "values" => self.select_stmt(true),
            "insert" => self.insert_stmt(),
            "update" => self.update_stmt(),
            "delete" => self.delete_stmt(),
            "prepare" => {
                let name = self.take_word()?;
                self.word("as")?;
                Ok(Statement::Prepare {
                    name,
                    sql: self.rest_text(),
                })
            }
            "execute" => {
                let name = self.take_word()?;
                let mut params = Vec::new();
                if self.eat(Tok::L) && !self.eat(Tok::R) {
                    loop {
                        params.push(self.expr()?);
                        if self.eat(Tok::R) {
                            break;
                        }
                        self.expect(Tok::Comma)?;
                    }
                }
                Ok(Statement::Execute { name, params })
            }
            "explain" | "with" | "merge" | "copy" => {
                Ok(Statement::Unsupported(format!("{w} is not supported")))
            }
            _ => Err(SqlError::new(
                "42601",
                format!("syntax error at or near \"{w}\""),
            )),
        }
    }
    fn set_stmt(&mut self) -> std::result::Result<Statement, SqlError> {
        let name = self.take_word()?;
        if self.eat_op("=") || self.eat_word("to") {}
        Ok(Statement::Set(name, self.rest_text()))
    }
    fn create_stmt(&mut self) -> std::result::Result<Statement, SqlError> {
        let kind = self.take_word()?;
        match kind.as_str() {
            "table" => {
                let if_not_exists = self.words(&["if", "not", "exists"]);
                let name = self.take_word()?;
                self.expect(Tok::L)?;
                let mut cols = Vec::new();
                let mut pk = Vec::new();
                loop {
                    if self.eat_word("primary") {
                        self.word("key")?;
                        self.expect(Tok::L)?;
                        pk = self.names_close()?;
                    } else {
                        let cname = self.take_word()?;
                        let ty = self.ty()?;
                        let mut nullable = true;
                        let mut default = None;
                        loop {
                            if self.words(&["not", "null"]) {
                                nullable = false;
                            } else if self.eat_word("null") {
                                nullable = true;
                            } else if self.eat_word("default") {
                                default = self.literal()?;
                            } else if self.words(&["primary", "key"]) {
                                pk.push(cname.clone());
                                nullable = false;
                            } else {
                                break;
                            }
                        }
                        cols.push(ColumnSpec {
                            name: cname,
                            ty,
                            nullable,
                            default,
                        });
                    }
                    if self.eat(Tok::R) {
                        break;
                    }
                    self.expect(Tok::Comma)?;
                }
                Ok(Statement::CreateTable {
                    name,
                    if_not_exists,
                    columns: cols,
                    primary_key: pk,
                })
            }
            "index" | "unique" => {
                let unique = kind == "unique";
                if unique {
                    self.word("index")?;
                }
                let if_not_exists = self.words(&["if", "not", "exists"]);
                let name = self.take_word()?;
                self.word("on")?;
                let table = self.take_word()?;
                self.expect(Tok::L)?;
                let mut columns = Vec::new();
                loop {
                    let n = self.take_word()?;
                    let desc = if self.eat_word("desc") {
                        true
                    } else {
                        self.eat_word("asc");
                        false
                    };
                    columns.push((n, desc));
                    if self.eat(Tok::R) {
                        break;
                    }
                    self.expect(Tok::Comma)?;
                }
                Ok(Statement::CreateIndex {
                    name,
                    table,
                    unique,
                    if_not_exists,
                    columns,
                })
            }
            _ => Err(SqlError::unsupported(format!(
                "CREATE {kind} is not supported"
            ))),
        }
    }
    fn drop_stmt(&mut self) -> std::result::Result<Statement, SqlError> {
        let k = self.take_word()?;
        let if_exists = self.words(&["if", "exists"]);
        let name = self.take_word()?;
        Ok(match k.as_str() {
            "table" => Statement::DropTable { name, if_exists },
            "index" => Statement::DropIndex { name, if_exists },
            _ => Statement::Unsupported(format!("DROP {k} is not supported")),
        })
    }
    fn alter_stmt(&mut self) -> std::result::Result<Statement, SqlError> {
        self.word("table")?;
        let table = self.take_word()?;
        let op = self.take_word()?;
        let alter = match op.as_str() {
            "add" => {
                self.eat_word("column");
                let name = self.take_word()?;
                let ty = self.ty()?;
                let nullable = !self.words(&["not", "null"]);
                let default = if self.eat_word("default") {
                    self.literal()?
                } else {
                    None
                };
                AlterOp::Add(ColumnSpec {
                    name,
                    ty,
                    nullable,
                    default,
                })
            }
            "drop" => {
                self.eat_word("column");
                AlterOp::Drop(self.take_word()?)
            }
            "rename" => {
                let old = self.take_word()?;
                if old == "to" {
                    AlterOp::RenameTable(self.take_word()?)
                } else {
                    self.word("to")?;
                    AlterOp::RenameColumn(old, self.take_word()?)
                }
            }
            _ => {
                return Err(SqlError::unsupported(format!(
                    "ALTER TABLE {op} is not supported"
                )));
            }
        };
        Ok(Statement::AlterTable { table, op: alter })
    }
    fn select_stmt(&mut self, values_only: bool) -> std::result::Result<Statement, SqlError> {
        let distinct = self.eat_word("distinct");
        let mut projection = Vec::new();
        loop {
            projection.push(if self.eat(Tok::Star) {
                Expr::Star
            } else {
                self.expr()?
            });
            if !self.eat(Tok::Comma) {
                break;
            }
        }
        let from = if values_only {
            None
        } else if self.eat_word("from") {
            Some(self.take_word()?)
        } else {
            None
        };
        let mut selection = None;
        let mut order = Vec::new();
        let mut limit = None;
        let mut offset = 0;
        while self.p < self.t.len() {
            if self.eat_word("where") {
                selection = Some(self.expr()?);
            } else if self.eat_word("order") {
                self.word("by")?;
                loop {
                    let e = self.expr()?;
                    let desc = if self.eat_word("desc") {
                        true
                    } else {
                        self.eat_word("asc");
                        false
                    };
                    order.push((e, desc));
                    if !self.eat(Tok::Comma) {
                        break;
                    }
                }
            } else if self.eat_word("limit") {
                limit = Some(self.int()? as usize);
            } else if self.eat_word("offset") {
                offset = self.int()? as usize;
            } else {
                return Err(SqlError::unsupported(format!(
                    "clause {:?} is not supported",
                    self.peek()
                )));
            }
        }
        Ok(Statement::Select(Select {
            projection,
            from,
            selection,
            order,
            limit,
            offset,
            distinct,
        }))
    }
    fn insert_stmt(&mut self) -> std::result::Result<Statement, SqlError> {
        self.word("into")?;
        let table = self.take_word()?;
        let mut columns = Vec::new();
        if self.eat(Tok::L) {
            columns = self.names_close()?;
        }
        self.word("values")?;
        let mut values = Vec::new();
        loop {
            self.expect(Tok::L)?;
            let mut row = Vec::new();
            loop {
                row.push(self.expr()?);
                if self.eat(Tok::R) {
                    break;
                }
                self.expect(Tok::Comma)?;
            }
            values.push(row);
            if !self.eat(Tok::Comma) {
                break;
            }
        }
        let conflict_nothing = if self.words(&["on", "conflict"]) {
            if self.eat(Tok::L) {
                self.names_close()?;
            }
            self.word("do")?;
            self.word("nothing")?;
            true
        } else {
            false
        };
        let returning = if self.eat_word("returning") {
            self.expr_list()?
        } else {
            Vec::new()
        };
        Ok(Statement::Insert(Insert {
            table,
            columns,
            values,
            returning,
            conflict_nothing,
        }))
    }
    fn update_stmt(&mut self) -> std::result::Result<Statement, SqlError> {
        let table = self.take_word()?;
        self.word("set")?;
        let mut assignments = Vec::new();
        loop {
            let n = self.take_word()?;
            self.expect_op("=")?;
            assignments.push((n, self.expr()?));
            if !self.eat(Tok::Comma) {
                break;
            }
        }
        let selection = if self.eat_word("where") {
            Some(self.expr()?)
        } else {
            None
        };
        let returning = if self.eat_word("returning") {
            self.expr_list()?
        } else {
            Vec::new()
        };
        Ok(Statement::Update(Update {
            table,
            assignments,
            selection,
            returning,
        }))
    }
    fn delete_stmt(&mut self) -> std::result::Result<Statement, SqlError> {
        self.word("from")?;
        let table = self.take_word()?;
        let selection = if self.eat_word("where") {
            Some(self.expr()?)
        } else {
            None
        };
        let returning = if self.eat_word("returning") {
            self.expr_list()?
        } else {
            Vec::new()
        };
        Ok(Statement::Delete(Delete {
            table,
            selection,
            returning,
        }))
    }
    fn expr_list(&mut self) -> std::result::Result<Vec<Expr>, SqlError> {
        let mut v = Vec::new();
        loop {
            v.push(self.expr()?);
            if !self.eat(Tok::Comma) {
                break;
            }
        }
        Ok(v)
    }
    fn names_close(&mut self) -> std::result::Result<Vec<String>, SqlError> {
        let mut v = Vec::new();
        loop {
            v.push(self.take_word()?);
            if self.eat(Tok::R) {
                break;
            }
            self.expect(Tok::Comma)?;
        }
        Ok(v)
    }
    fn ty(&mut self) -> std::result::Result<SqlType, SqlError> {
        let n = self.take_word()?;
        Ok(match n.as_str() {
            "bool" | "boolean" => SqlType::Boolean,
            "bytea" => SqlType::Bytea,
            "smallint" | "int2" => SqlType::SmallInt,
            "int" | "integer" | "int4" => SqlType::Integer,
            "bigint" | "int8" => SqlType::BigInt,
            "text" => SqlType::Text,
            "varchar" | "character" => {
                if n == "character" {
                    self.word("varying")?;
                }
                let len = if self.eat(Tok::L) {
                    let n = self.int()?;
                    self.expect(Tok::R)?;
                    Some(n as u32)
                } else {
                    None
                };
                SqlType::Varchar(len)
            }
            "float" | "double" => {
                if n == "double" {
                    self.eat_word("precision");
                }
                SqlType::Double
            }
            "date" => SqlType::Date,
            "timestamp" => {
                if self.words(&["with", "time", "zone"]) {
                    SqlType::TimestampTz
                } else {
                    SqlType::Timestamp
                }
            }
            "timestamptz" => SqlType::TimestampTz,
            "uuid" => SqlType::Uuid,
            "jsonb" => SqlType::Jsonb,
            _ => return Err(SqlError::unsupported(format!("type {n} is not supported"))),
        })
    }
    fn literal(&mut self) -> std::result::Result<Option<Datum>, SqlError> {
        match self.next() {
            Some(Tok::Str(s)) => Ok(Some(Datum::Text(s))),
            Some(Tok::Num(n)) => Ok(Some(if n.contains('.') {
                Datum::Float64(
                    n.parse()
                        .map_err(|_| SqlError::new("22P02", "invalid float"))?,
                )
            } else {
                Datum::Int64(
                    n.parse()
                        .map_err(|_| SqlError::new("22P02", "invalid integer"))?,
                )
            })),
            Some(Tok::Word(w)) if w == "true" => Ok(Some(Datum::Boolean(true))),
            Some(Tok::Word(w)) if w == "false" => Ok(Some(Datum::Boolean(false))),
            Some(Tok::Word(w)) if w == "null" => Ok(Some(Datum::Null)),
            Some(x) => Err(SqlError::new(
                "42601",
                format!("expected literal, got {x:?}"),
            )),
            None => Err(SqlError::new("42601", "expected literal")),
        }
    }
    fn expr(&mut self) -> std::result::Result<Expr, SqlError> {
        self.prec(0)
    }
    fn prec(&mut self, min: u8) -> std::result::Result<Expr, SqlError> {
        let mut left = self.primary()?;
        loop {
            let (op, p) = match self.binary() {
                Some(x) => x,
                None => break,
            };
            if p < min {
                break;
            }
            self.next();
            let right = self.prec(p + 1)?;
            left = Expr::Binary(Box::new(left), op, Box::new(right));
        }
        Ok(left)
    }
    fn primary(&mut self) -> std::result::Result<Expr, SqlError> {
        let mut e = match self.next() {
            Some(Tok::Num(n)) => Expr::Literal(if n.contains('.') {
                Datum::Float64(
                    n.parse()
                        .map_err(|_| SqlError::new("22P02", "invalid number"))?,
                )
            } else {
                Datum::Int64(
                    n.parse()
                        .map_err(|_| SqlError::new("22P02", "invalid number"))?,
                )
            }),
            Some(Tok::Str(s)) => Expr::Literal(Datum::Text(s)),
            Some(Tok::Param(n)) => Expr::Param(n),
            Some(Tok::Star) => Expr::Star,
            Some(Tok::Word(w)) if w == "null" => Expr::Literal(Datum::Null),
            Some(Tok::Word(w)) if w == "true" => Expr::Literal(Datum::Boolean(true)),
            Some(Tok::Word(w)) if w == "false" => Expr::Literal(Datum::Boolean(false)),
            Some(Tok::Word(w)) if w == "not" => Expr::Unary(Unary::Not, Box::new(self.primary()?)),
            Some(Tok::Word(w)) if w == "case" => self.case_expr()?,
            Some(Tok::Word(w)) => {
                if self.eat(Tok::L) {
                    let mut args = Vec::new();
                    if !self.eat(Tok::R) {
                        args = self.expr_list()?;
                        self.expect(Tok::R)?;
                    }
                    Expr::Func(w, args)
                } else if self.eat(Tok::Dot) {
                    Expr::Qualified(w, self.take_word()?)
                } else {
                    Expr::Column(w)
                }
            }
            Some(Tok::Op(op)) if op == "-" => Expr::Unary(Unary::Neg, Box::new(self.primary()?)),
            Some(Tok::L) => {
                let x = self.expr()?;
                self.expect(Tok::R)?;
                x
            }
            Some(x) => return Err(SqlError::new("42601", format!("unexpected token {x:?}"))),
            None => return Err(SqlError::new("42601", "unexpected end of input")),
        };
        loop {
            if self.eat_word("is") { let not = self.eat_word("not"); self.word("null")?; e = Expr::IsNull(Box::new(e), not); } else if self.peek_word("in") || self.peek_word("between") || self.peek_word("like") || (self.peek_word("not") && self.t.get(self.p + 1).map(|t| matches!(t, Tok::Word(w) if w == "in" || w == "between" || w == "like")).unwrap_or(false)) { let not = self.eat_word("not"); if self.eat_word("in") { self.expect(Tok::L)?; let mut v = Vec::new(); loop { v.push(self.expr()?); if self.eat(Tok::R) { break; } self.expect(Tok::Comma)?; } e = Expr::In(Box::new(e), v, not); } else if self.eat_word("between") { let lo = self.expr()?; self.word("and")?; let hi = self.expr()?; e = Expr::Between(Box::new(e), Box::new(lo), Box::new(hi), not); } else { self.word("like")?; e = Expr::Like(Box::new(e), Box::new(self.primary()?), not); } } else { break; }
        }
        Ok(e)
    }
    fn case_expr(&mut self) -> std::result::Result<Expr, SqlError> {
        let mut b = Vec::new();
        while self.eat_word("when") {
            let w = self.expr()?;
            self.word("then")?;
            b.push((w, self.expr()?));
        }
        let e = if self.eat_word("else") {
            self.expr()?
        } else {
            Expr::Literal(Datum::Null)
        };
        self.word("end")?;
        Ok(Expr::Case(b, Box::new(e)))
    }
    fn binary(&self) -> Option<(BinOp, u8)> {
        match self.peek() {
            Some(Tok::Word(w)) if w == "or" => Some((BinOp::Or, 1)),
            Some(Tok::Word(w)) if w == "and" => Some((BinOp::And, 2)),
            Some(Tok::Op(o)) => Some(match o.as_str() {
                "=" => (BinOp::Eq, 3),
                "<>" | "!=" => (BinOp::Ne, 3),
                "<" => (BinOp::Lt, 3),
                "<=" => (BinOp::Le, 3),
                ">" => (BinOp::Gt, 3),
                ">=" => (BinOp::Ge, 3),
                "+" => (BinOp::Add, 4),
                "-" => (BinOp::Sub, 4),
                "||" => (BinOp::Concat, 4),
                "*" => (BinOp::Mul, 5),
                "/" => (BinOp::Div, 5),
                _ => return None,
            }),
            _ => None,
        }
    }
    fn rest_text(&self) -> String {
        self.t[self.p..]
            .iter()
            .map(tok_text)
            .collect::<Vec<_>>()
            .join(" ")
    }
    fn int(&mut self) -> std::result::Result<i64, SqlError> {
        match self.next() {
            Some(Tok::Num(n)) => n
                .parse()
                .map_err(|_| SqlError::new("22P02", "invalid integer")),
            Some(Tok::Op(o)) if o == "-" => match self.next() {
                Some(Tok::Num(n)) => n
                    .parse::<i64>()
                    .map(|v| -v)
                    .map_err(|_| SqlError::new("22P02", "invalid integer")),
                _ => Err(SqlError::new("42601", "expected integer")),
            },
            _ => Err(SqlError::new("42601", "expected integer")),
        }
    }
    fn take_word(&mut self) -> std::result::Result<String, SqlError> {
        match self.next() {
            Some(Tok::Word(w)) => Ok(w),
            x => Err(SqlError::new(
                "42601",
                format!("expected identifier, got {x:?}"),
            )),
        }
    }
    fn word(&mut self, w: &str) -> std::result::Result<(), SqlError> {
        if self.eat_word(w) {
            Ok(())
        } else {
            Err(SqlError::new("42601", format!("expected {w}")))
        }
    }
    fn eat_word(&mut self, w: &str) -> bool {
        if self.peek_word(w) {
            self.p += 1;
            true
        } else {
            false
        }
    }
    fn words(&mut self, ws: &[&str]) -> bool {
        let s = self.p;
        for w in ws {
            if !self.eat_word(w) {
                self.p = s;
                return false;
            }
        }
        true
    }
    fn peek_word(&self, w: &str) -> bool {
        matches!(self.peek(), Some(Tok::Word(x)) if x == w)
    }
    fn expect_op(&mut self, op: &str) -> std::result::Result<(), SqlError> {
        if self.eat_op(op) {
            Ok(())
        } else {
            Err(SqlError::new("42601", format!("expected {op}")))
        }
    }
    fn eat_op(&mut self, op: &str) -> bool {
        matches!(self.peek(), Some(Tok::Op(x)) if x == op) && {
            self.p += 1;
            true
        }
    }
    fn expect(&mut self, t: Tok) -> std::result::Result<(), SqlError> {
        if self.eat(t.clone()) {
            Ok(())
        } else {
            Err(SqlError::new("42601", format!("expected {t:?}")))
        }
    }
    fn eat(&mut self, t: Tok) -> bool {
        if self.peek() == Some(&t) {
            self.p += 1;
            true
        } else {
            false
        }
    }
    fn next(&mut self) -> Option<Tok> {
        let v = self.t.get(self.p).cloned();
        if v.is_some() {
            self.p += 1;
        }
        v
    }
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.p)
    }
}
fn tok_text(t: &Tok) -> String {
    match t {
        Tok::Word(s) => s.clone(),
        Tok::Str(s) => format!("'{s}'"),
        Tok::Num(s) => s.clone(),
        Tok::Param(n) => format!("${n}"),
        Tok::Op(s) => s.clone(),
        Tok::L => "(".into(),
        Tok::R => ")".into(),
        Tok::Comma => ",".into(),
        Tok::Dot => ".".into(),
        Tok::Semi => ";".into(),
        Tok::Star => "*".into(),
    }
}

pub struct SqlSession {
    engine: Arc<SqlEngine>,
    txn: Option<Transaction>,
    failed: bool,
    settings: SessionSettings,
    prepared: HashMap<String, String>,
    sequencer: Arc<CommitSequencer>,
}
impl SqlSession {
    pub fn settings(&self) -> &SessionSettings {
        &self.settings
    }
    pub fn set_param(&mut self, name: &str, value: &str) -> std::result::Result<(), SqlError> {
        set_setting(&mut self.settings, name, value)
    }
    pub fn prepared_sql(&self, name: &str) -> Option<&str> {
        self.prepared.get(name).map(String::as_str)
    }
    pub fn transaction_status(&self) -> TransactionStatus {
        if self.failed {
            TransactionStatus::Failed
        } else {
            self.txn
                .as_ref()
                .map(|t| t.status)
                .unwrap_or(TransactionStatus::Aborted)
        }
    }
    pub fn execute(
        &mut self,
        sql: &str,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        if sql.len() > self.engine.limits.max_sql_message_bytes {
            return Err(SqlError::new(
                "54000",
                "SQL message exceeds configured limit",
            ));
        }
        let statements = Parser::batch(sql)?;
        if statements.is_empty() {
            return Ok(QueryResult::command("", 0));
        }
        if statements.iter().any(|s| s.is_ddl()) && statements.len() != 1 {
            return Err(SqlError::new(
                "25001",
                "DDL statements must be executed alone in the MVP",
            ));
        }
        let implicit = self.txn.is_none()
            && !statements.iter().any(Statement::txn_control)
            && !statements.iter().any(Statement::is_ddl);
        if implicit {
            self.start_txn()?;
        }
        let mut last = QueryResult::command("", 0);
        for statement in statements {
            match self.exec_statement(statement, params) {
                Ok(r) => last = r,
                Err(e) => {
                    if implicit {
                        self.rollback_internal();
                    } else if self.txn.is_some() && e.code != "25P02" {
                        self.failed = true;
                        if let Some(t) = self.txn.as_mut() {
                            t.fail();
                        }
                    }
                    return Err(e);
                }
            }
        }
        if implicit {
            self.commit_internal()?;
        }
        Ok(last)
    }
    pub fn prepare(&mut self, name: &str, sql: &str) -> std::result::Result<(), SqlError> {
        Parser::batch(sql)?;
        self.prepared.insert(name.into(), sql.into());
        Ok(())
    }
    pub fn execute_prepared(
        &mut self,
        name: &str,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        let sql = self
            .prepared
            .get(name)
            .cloned()
            .ok_or_else(|| SqlError::new("26000", "prepared statement does not exist"))?;
        self.execute(&sql, params)
    }
    fn exec_statement(
        &mut self,
        s: Statement,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        match s {
            Statement::Begin { read_only } => {
                if self.txn.is_some() {
                    return Err(SqlError::new("25001", "transaction already in progress"));
                }
                self.start_txn()?;
                self.txn.as_mut().unwrap().read_only = read_only;
                Ok(QueryResult::command("BEGIN", 0))
            }
            Statement::Commit => {
                if self.failed {
                    self.rollback_internal();
                    return Ok(QueryResult::command("ROLLBACK", 0));
                }
                self.commit_internal()?;
                Ok(QueryResult::command("COMMIT", 0))
            }
            Statement::Rollback => {
                self.rollback_internal();
                Ok(QueryResult::command("ROLLBACK", 0))
            }
            Statement::Set(n, v) => {
                set_setting(&mut self.settings, &n, &v)?;
                Ok(QueryResult::command("SET", 0))
            }
            Statement::Show(n) => self.show(&n),
            Statement::CreateTable { .. }
            | Statement::DropTable { .. }
            | Statement::AlterTable { .. }
            | Statement::CreateIndex { .. }
            | Statement::DropIndex { .. } => self.ddl(s),
            Statement::Select(q) => self.select(q, params),
            Statement::Insert(q) => self.insert(q, params),
            Statement::Update(q) => self.update(q, params),
            Statement::Delete(q) => self.delete(q, params),
            Statement::Prepare { name, sql } => {
                self.prepare(&name, &sql)?;
                Ok(QueryResult::command("PREPARE", 0))
            }
            Statement::Execute { name, params: ps } => {
                let mut p = Vec::new();
                for e in ps {
                    p.push(self.eval(&e, &[], params)?);
                }
                self.execute_prepared(&name, &p)
            }
            Statement::Unsupported(m) => Err(SqlError::unsupported(m)),
        }
    }
    fn start_txn(&mut self) -> std::result::Result<(), SqlError> {
        let snapshot = self.engine.committer.read_barrier().map_err(to_sql)?;
        self.txn = Some(Transaction::begin(snapshot, self.engine.limits.clone()));
        self.failed = false;
        Ok(())
    }
    fn commit_internal(&mut self) -> std::result::Result<(), SqlError> {
        if let Some(mut txn) = self.txn.take() {
            let r = txn
                .commit(self.engine.committer.as_ref(), &self.sequencer)
                .map_err(to_sql)?;
            if matches!(r, ApplyResult::SerializationFailure { .. }) {
                return Err(SqlError::serialization(
                    "could not serialize access due to concurrent update",
                ));
            }
        }
        self.failed = false;
        Ok(())
    }
    fn rollback_internal(&mut self) {
        if let Some(t) = self.txn.as_mut() {
            t.rollback();
        }
        self.txn = None;
        self.failed = false;
    }
    fn tx(&mut self) -> std::result::Result<&mut Transaction, SqlError> {
        if self.failed {
            return Err(SqlError::failed_transaction());
        }
        if self.txn.is_none() {
            self.start_txn()?;
        }
        Ok(self.txn.as_mut().unwrap())
    }
    fn show(&self, name: &str) -> std::result::Result<QueryResult, SqlError> {
        let n = name.to_ascii_lowercase();
        let v = match n.as_str() {
            "application_name" => self.settings.application_name.clone(),
            "search_path" => self.settings.search_path.clone(),
            "client_encoding" => self.settings.client_encoding.clone(),
            "timezone" => self.settings.timezone.clone(),
            "datestyle" => self.settings.datestyle.clone(),
            "transaction_isolation" => self.settings.transaction_isolation.clone(),
            "transaction_read_only" => self.settings.transaction_read_only.to_string(),
            "server_version" => "16.0 (Chorus MVP)".into(),
            "server_version_num" => "160000".into(),
            "integer_datetimes" => "on".into(),
            "standard_conforming_strings" => {
                if self.settings.standard_conforming_strings {
                    "on".into()
                } else {
                    "off".into()
                }
            }
            "bytea_output" => self.settings.bytea_output.clone(),
            _ => {
                return Err(SqlError::new(
                    "42704",
                    "unrecognized configuration parameter",
                ));
            }
        };
        Ok(QueryResult {
            columns: vec![ResultColumn {
                name: name.into(),
                data_type: SqlType::Text,
                table_oid: 0,
                column_oid: 0,
            }],
            rows: vec![vec![Datum::Text(v)]],
            command_tag: "SHOW".into(),
            affected_rows: 1,
            notices: Vec::new(),
        })
    }
    fn ddl(&mut self, s: Statement) -> std::result::Result<QueryResult, SqlError> {
        if self.txn.is_some() {
            return Err(SqlError::new(
                "25001",
                "DDL cannot run inside an explicit transaction",
            ));
        }
        let snap = self.engine.committer.read_barrier().map_err(to_sql)?;
        let (op, tag) = bind_ddl(s, &snap)?;
        let r = self
            .sequencer
            .submit_schema(self.engine.committer.as_ref(), snap.db_epoch(), op)
            .map_err(to_sql)?;
        match r {
            ApplyResult::Committed { .. } | ApplyResult::Duplicate(_) => {
                Ok(QueryResult::command(tag, 0))
            }
            ApplyResult::SerializationFailure { .. } => {
                Err(SqlError::serialization("could not serialize schema change"))
            }
            ApplyResult::Rejected(m) | ApplyResult::ProtocolError(m) => {
                Err(SqlError::new("XX000", m))
            }
            _ => Err(SqlError::new("XX000", "schema change did not commit")),
        }
    }

    /*
    fn select(&mut self, q: Select, params: &[Datum]) -> std::result::Result<QueryResult, SqlError> {
        let tx = self.tx()?; tx.set_statement_time(); let table = q.from.as_ref().map(|n| find_table(tx.snapshot.catalog(), n)).transpose()?;
        if let Some(table) = table { let mut rows = scan(tx, table)?; if let Some(w) = &q.selection { rows.retain(|r| self.eval(w, &r.cells, params).map(|v| v.truthy() == Some(true)).unwrap_or(false)); } for (e, desc) in q.order.iter().rev() { rows.sort_by(|a, b| { let x = self.eval(e, &a.cells, params).unwrap_or(Datum::Null); let y = self.eval(e, &b.cells, params).unwrap_or(Datum::Null); let mut c = x.cmp(&y); if x.is_null() || y.is_null() { c = if x.is_null() && y.is_null() { std::cmp::Ordering::Equal } else if x.is_null() { std::cmp::Ordering::Greater } else { std::cmp::Ordering::Less }; } if *desc { c.reverse() } else { c } }); } let rows = rows.into_iter().skip(q.offset).take(q.limit.unwrap_or(usize::MAX)).collect::<Vec<_>>(); let projection = if q.projection.len() == 1 && matches!(q.projection[0], Expr::Star) { table.columns.iter().filter(|c| c.state == ColumnState::Live).map(|c| Expr::Column(c.name.clone())).collect::<Vec<_>>() } else { q.projection }; let columns = projection.iter().map(|e| result_column(e, table)).collect(); let mut out = Vec::new(); for r in rows { let values = projection.iter().map(|e| self.eval(e, &r.cells, params)).collect::<std::result::Result<Vec<_>, _>>()?; if q.distinct && out.iter().any(|v: &Vec<Datum>| v == &values) { continue; } out.push(values); } Ok(QueryResult { columns, affected_rows: out.len() as u64, rows: out, command_tag: "SELECT".into(), notices: Vec::new() }) } else { let columns = q.projection.iter().map(|e| result_column(e, dummy_table())).collect(); let row = q.projection.iter().map(|e| self.eval(e, &[], params)).collect::<std::result::Result<Vec<_>, _>>()?; Ok(QueryResult { columns, rows: vec![row], affected_rows: 1, command_tag: "SELECT".into(), notices: Vec::new() }) }
    }

    fn insert(&mut self, q: Insert, params: &[Datum]) -> std::result::Result<QueryResult, SqlError> { let tx = self.tx()?; tx.set_statement_time(); let table = find_table(tx.snapshot.catalog(), &q.table)?; let cols: Vec<_> = if q.columns.is_empty() { table.columns.iter().filter(|c| c.state == ColumnState::Live).cloned().collect() } else { q.columns.iter().map(|n| table.columns.iter().find(|c| c.name == *n && c.state == ColumnState::Live).cloned().ok_or_else(|| SqlError::new("42703", format!("column {n} does not exist")))).collect::<std::result::Result<Vec<_>, _>>()? }; let mut ret = Vec::new(); let mut count = 0u64; for (i, vals) in q.values.iter().enumerate() { if vals.len() != cols.len() { return Err(SqlError::new("42601", "INSERT has mismatched values")); } let mut fields = Vec::new(); for (c, e) in cols.iter().zip(vals) { fields.push((c.id, coerce(self.eval(e, &[], params)?, c.data_type)?)); } for c in table.columns.iter().filter(|c| c.state == ColumnState::Live) { if !fields.iter().any(|(id, _)| *id == c.id) { let v = c.default.clone().unwrap_or(Datum::Null); if v.is_null() && !c.nullable { return Err(SqlError::new("23502", format!("null value in column {} violates not-null constraint", c.name))); } fields.push((c.id, v)); } } let row = chorus_codec::EncodedRowV1::new(table.schema_version, fields).map_err(codec_sql)?; let key = key_for(tx, table, &row, i as u32)?; if tx.get(&key).is_some() { if q.conflict_nothing { continue; } return Err(SqlError::new("23505", "duplicate key value violates unique constraint")); } tx.put(key, row.encode().map_err(codec_sql)?).map_err(to_sql)?; count += 1; if !q.returning.is_empty() { ret.push(self.returning(&q.returning, table, &row, params)?); } } Ok(QueryResult { columns: q.returning.iter().map(|e| result_column(e, table)).collect(), rows: ret, affected_rows: count, command_tag: format!("INSERT 0 {count}"), notices: Vec::new() }) }

    fn update(&mut self, q: Update, params: &[Datum]) -> std::result::Result<QueryResult, SqlError> { let tx = self.tx()?; tx.set_statement_time(); let table = find_table(tx.snapshot.catalog(), &q.table)?; let targets = scan(tx, table)?; let mut ret = Vec::new(); let mut count = 0u32; for target in targets { if let Some(w) = &q.selection { if self.eval(w, &target.cells, params)?.truthy() != Some(true) { continue; } } let mut row = target.row.clone(); for (n, e) in &q.assignments { let c = table.columns.iter().find(|c| c.name == *n && c.state == ColumnState::Live).ok_or_else(|| SqlError::new("42703", format!("column {n} does not exist")))?; let v = coerce(self.eval(e, &target.cells, params)?, c.data_type)?; if let Some(x) = row.fields.iter_mut().find(|(id, _)| *id == c.id) { x.1 = v; } else { row.fields.push((c.id, v)); } } row.fields.sort_by_key(|(id, _)| *id); tx.delete(target.key).map_err(to_sql)?; let new_key = key_for(tx, table, &row, count)?; tx.put(new_key, row.encode().map_err(codec_sql)?).map_err(to_sql)?; if !q.returning.is_empty() { ret.push(self.returning(&q.returning, table, &row, params)?); } count += 1; } Ok(QueryResult { columns: q.returning.iter().map(|e| result_column(e, table)).collect(), rows: ret, affected_rows: count as u64, command_tag: format!("UPDATE {count}"), notices: Vec::new() }) }

    fn delete(&mut self, q: Delete, params: &[Datum]) -> std::result::Result<QueryResult, SqlError> { let tx = self.tx()?; tx.set_statement_time(); let table = find_table(tx.snapshot.catalog(), &q.table)?; let targets = scan(tx, table)?; let mut ret = Vec::new(); let mut count = 0u64; for target in targets { if let Some(w) = &q.selection { if self.eval(w, &target.cells, params)?.truthy() != Some(true) { continue; } } if !q.returning.is_empty() { ret.push(self.returning(&q.returning, table, &target.row, params)?); } tx.delete(target.key).map_err(to_sql)?; count += 1; } Ok(QueryResult { columns: q.returning.iter().map(|e| result_column(e, table)).collect(), rows: ret, affected_rows: count, command_tag: format!("DELETE {count}"), notices: Vec::new() }) }

    */
    fn select(
        &mut self,
        q: Select,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        if self.txn.is_none() {
            self.start_txn()?;
        }
        let mut tx = self.txn.take().expect("transaction initialized");
        let result = self.select_tx(&mut tx, q, params);
        self.txn = Some(tx);
        result
    }
    fn select_tx(
        &self,
        tx: &mut Transaction,
        q: Select,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        tx.set_statement_time();
        let table = q
            .from
            .as_ref()
            .map(|n| find_table(tx.snapshot.catalog(), n))
            .transpose()?
            .cloned();
        if let Some(table) = table {
            let mut rows = scan(tx, &table)?;
            if let Some(w) = &q.selection {
                rows.retain(|r| {
                    self.eval(w, &r.cells, params)
                        .map(|v| v.truthy() == Some(true))
                        .unwrap_or(false)
                });
            }
            for (e, desc) in q.order.iter().rev() {
                rows.sort_by(|a, b| {
                    let x = self.eval(e, &a.cells, params).unwrap_or(Datum::Null);
                    let y = self.eval(e, &b.cells, params).unwrap_or(Datum::Null);
                    let mut c = x.cmp(&y);
                    if x.is_null() || y.is_null() {
                        c = if x.is_null() && y.is_null() {
                            std::cmp::Ordering::Equal
                        } else if x.is_null() {
                            std::cmp::Ordering::Greater
                        } else {
                            std::cmp::Ordering::Less
                        };
                    }
                    if *desc { c.reverse() } else { c }
                });
            }
            let rows = rows
                .into_iter()
                .skip(q.offset)
                .take(q.limit.unwrap_or(usize::MAX))
                .collect::<Vec<_>>();
            let projection = if q.projection.len() == 1 && matches!(q.projection[0], Expr::Star) {
                table
                    .columns
                    .iter()
                    .filter(|c| c.state == ColumnState::Live)
                    .map(|c| Expr::Column(c.name.clone()))
                    .collect::<Vec<_>>()
            } else {
                q.projection
            };
            let columns = projection
                .iter()
                .map(|e| result_column(e, &table))
                .collect();
            let mut out = Vec::new();
            for r in rows {
                let values = projection
                    .iter()
                    .map(|e| self.eval(e, &r.cells, params))
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                if q.distinct && out.iter().any(|v: &Vec<Datum>| v == &values) {
                    continue;
                }
                out.push(values);
            }
            Ok(QueryResult {
                columns,
                affected_rows: out.len() as u64,
                rows: out,
                command_tag: "SELECT".into(),
                notices: Vec::new(),
            })
        } else {
            let columns = q
                .projection
                .iter()
                .map(|e| result_column(e, dummy_table()))
                .collect();
            let row = q
                .projection
                .iter()
                .map(|e| self.eval(e, &[], params))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok(QueryResult {
                columns,
                rows: vec![row],
                affected_rows: 1,
                command_tag: "SELECT".into(),
                notices: Vec::new(),
            })
        }
    }
    fn insert(
        &mut self,
        q: Insert,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        if self.txn.is_none() {
            self.start_txn()?;
        }
        let mut tx = self.txn.take().expect("transaction initialized");
        let result = self.insert_tx(&mut tx, q, params);
        self.txn = Some(tx);
        result
    }
    fn insert_tx(
        &self,
        tx: &mut Transaction,
        q: Insert,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        tx.set_statement_time();
        let table = find_table(tx.snapshot.catalog(), &q.table)?.clone();
        let cols: Vec<_> = if q.columns.is_empty() {
            table
                .columns
                .iter()
                .filter(|c| c.state == ColumnState::Live)
                .cloned()
                .collect()
        } else {
            q.columns
                .iter()
                .map(|n| {
                    table
                        .columns
                        .iter()
                        .find(|c| c.name == *n && c.state == ColumnState::Live)
                        .cloned()
                        .ok_or_else(|| SqlError::new("42703", format!("column {n} does not exist")))
                })
                .collect::<std::result::Result<Vec<_>, _>>()?
        };
        let mut ret = Vec::new();
        let mut count = 0u64;
        for (i, vals) in q.values.iter().enumerate() {
            if vals.len() != cols.len() {
                return Err(SqlError::new("42601", "INSERT has mismatched values"));
            }
            let mut fields = Vec::new();
            for (c, e) in cols.iter().zip(vals) {
                fields.push((c.id, coerce(self.eval(e, &[], params)?, c.data_type)?));
            }
            for c in table
                .columns
                .iter()
                .filter(|c| c.state == ColumnState::Live)
            {
                if !fields.iter().any(|(id, _)| *id == c.id) {
                    let v = c.default.clone().unwrap_or(Datum::Null);
                    if v.is_null() && !c.nullable {
                        return Err(SqlError::new(
                            "23502",
                            format!(
                                "null value in column {} violates not-null constraint",
                                c.name
                            ),
                        ));
                    }
                    fields.push((c.id, v));
                }
            }
            let row =
                chorus_codec::EncodedRowV1::new(table.schema_version, fields).map_err(codec_sql)?;
            let key = key_for(tx, &table, &row, i as u32)?;
            if tx.get(&key).is_some() {
                if q.conflict_nothing {
                    continue;
                }
                return Err(SqlError::new(
                    "23505",
                    "duplicate key value violates unique constraint",
                ));
            }
            tx.put(key, row.encode().map_err(codec_sql)?)
                .map_err(to_sql)?;
            count += 1;
            if !q.returning.is_empty() {
                ret.push(self.returning(&q.returning, &table, &row, params)?);
            }
        }
        Ok(QueryResult {
            columns: q
                .returning
                .iter()
                .map(|e| result_column(e, &table))
                .collect(),
            rows: ret,
            affected_rows: count,
            command_tag: format!("INSERT 0 {count}"),
            notices: Vec::new(),
        })
    }
    fn update(
        &mut self,
        q: Update,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        if self.txn.is_none() {
            self.start_txn()?;
        }
        let mut tx = self.txn.take().expect("transaction initialized");
        let result = self.update_tx(&mut tx, q, params);
        self.txn = Some(tx);
        result
    }
    fn update_tx(
        &self,
        tx: &mut Transaction,
        q: Update,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        tx.set_statement_time();
        let table = find_table(tx.snapshot.catalog(), &q.table)?.clone();
        let targets = scan(tx, &table)?;
        let mut ret = Vec::new();
        let mut count = 0u64;
        for target in targets {
            if let Some(w) = &q.selection {
                if self.eval(w, &target.cells, params)?.truthy() != Some(true) {
                    continue;
                }
            }
            let mut row = target.row.clone();
            for (n, e) in &q.assignments {
                let c = table
                    .columns
                    .iter()
                    .find(|c| c.name == *n && c.state == ColumnState::Live)
                    .ok_or_else(|| SqlError::new("42703", format!("column {n} does not exist")))?;
                let v = coerce(self.eval(e, &target.cells, params)?, c.data_type)?;
                if let Some(x) = row.fields.iter_mut().find(|(id, _)| *id == c.id) {
                    x.1 = v;
                } else {
                    row.fields.push((c.id, v));
                }
            }
            row.fields.sort_by_key(|(id, _)| *id);
            tx.delete(target.key).map_err(to_sql)?;
            let new_key = key_for(tx, &table, &row, count as u32)?;
            tx.put(new_key, row.encode().map_err(codec_sql)?)
                .map_err(to_sql)?;
            if !q.returning.is_empty() {
                ret.push(self.returning(&q.returning, &table, &row, params)?);
            }
            count += 1;
        }
        Ok(QueryResult {
            columns: q
                .returning
                .iter()
                .map(|e| result_column(e, &table))
                .collect(),
            rows: ret,
            affected_rows: count,
            command_tag: format!("UPDATE {count}"),
            notices: Vec::new(),
        })
    }
    fn delete(
        &mut self,
        q: Delete,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        if self.txn.is_none() {
            self.start_txn()?;
        }
        let mut tx = self.txn.take().expect("transaction initialized");
        let result = self.delete_tx(&mut tx, q, params);
        self.txn = Some(tx);
        result
    }
    fn delete_tx(
        &self,
        tx: &mut Transaction,
        q: Delete,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        tx.set_statement_time();
        let table = find_table(tx.snapshot.catalog(), &q.table)?.clone();
        let targets = scan(tx, &table)?;
        let mut ret = Vec::new();
        let mut count = 0u64;
        for target in targets {
            if let Some(w) = &q.selection {
                if self.eval(w, &target.cells, params)?.truthy() != Some(true) {
                    continue;
                }
            }
            if !q.returning.is_empty() {
                ret.push(self.returning(&q.returning, &table, &target.row, params)?);
            }
            tx.delete(target.key).map_err(to_sql)?;
            count += 1;
        }
        Ok(QueryResult {
            columns: q
                .returning
                .iter()
                .map(|e| result_column(e, &table))
                .collect(),
            rows: ret,
            affected_rows: count,
            command_tag: format!("DELETE {count}"),
            notices: Vec::new(),
        })
    }

    fn returning(
        &self,
        exprs: &[Expr],
        table: &TableDescriptor,
        row: &chorus_codec::EncodedRowV1,
        params: &[Datum],
    ) -> std::result::Result<Vec<Datum>, SqlError> {
        let cs = cells(table, row);
        exprs.iter().map(|e| self.eval(e, &cs, params)).collect()
    }
    fn eval(
        &self,
        e: &Expr,
        row: &[Cell],
        params: &[Datum],
    ) -> std::result::Result<Datum, SqlError> {
        match e {
            Expr::Literal(v) => Ok(v.clone()),
            Expr::Param(n) => params
                .get(n - 1)
                .cloned()
                .ok_or_else(|| SqlError::new("42P02", "missing parameter")),
            Expr::Column(n) => row
                .iter()
                .find(|c| c.name == *n)
                .map(|c| c.value.clone())
                .ok_or_else(|| SqlError::new("42703", format!("column {n} does not exist"))),
            Expr::Qualified(_, n) => self.eval(&Expr::Column(n.clone()), row, params),
            Expr::Star => Err(SqlError::new("42601", "* is only valid in a SELECT list")),
            Expr::Unary(op, x) => {
                let v = self.eval(x, row, params)?;
                match op {
                    Unary::Not => Ok(v
                        .as_bool()
                        .map(|b| Datum::Boolean(!b))
                        .unwrap_or(Datum::Null)),
                    Unary::Neg => {
                        if let Some(i) = v.as_i64() {
                            Ok(Datum::Int64(i.checked_neg().ok_or_else(|| {
                                SqlError::new("22003", "integer out of range")
                            })?))
                        } else {
                            Ok(Datum::Float64(-v.as_f64().ok_or_else(|| {
                                SqlError::new("42804", "operator does not exist")
                            })?))
                        }
                    }
                }
            }
            Expr::Binary(a, op, b) => eval_binary(
                &self.eval(a, row, params)?,
                *op,
                &self.eval(b, row, params)?,
            ),
            Expr::IsNull(x, not) => Ok(Datum::Boolean(self.eval(x, row, params)?.is_null() ^ *not)),
            Expr::In(x, xs, not) => {
                let v = self.eval(x, row, params)?;
                let mut found = false;
                let mut null = false;
                for y in xs {
                    let c = eval_binary(&v, BinOp::Eq, &self.eval(y, row, params)?)?;
                    if c.is_null() {
                        null = true;
                    } else if c.as_bool() == Some(true) {
                        found = true;
                        break;
                    }
                }
                Ok(if found {
                    Datum::Boolean(!not)
                } else if null {
                    Datum::Null
                } else {
                    Datum::Boolean(*not)
                })
            }
            Expr::Between(x, lo, hi, not) => {
                let a = eval_binary(
                    &self.eval(x, row, params)?,
                    BinOp::Ge,
                    &self.eval(lo, row, params)?,
                )?;
                let b = eval_binary(
                    &self.eval(x, row, params)?,
                    BinOp::Le,
                    &self.eval(hi, row, params)?,
                )?;
                let v = if a.as_bool() == Some(true) && b.as_bool() == Some(true) {
                    Some(true)
                } else if a.is_null() || b.is_null() {
                    None
                } else {
                    Some(false)
                };
                Ok(v.map(|x| Datum::Boolean(if *not { !x } else { x }))
                    .unwrap_or(Datum::Null))
            }
            Expr::Like(x, pat, not) => {
                let a = self.eval(x, row, params)?.display_text();
                let b = self.eval(pat, row, params)?.display_text();
                Ok(Datum::Boolean(if *not {
                    !like(&a, &b)
                } else {
                    like(&a, &b)
                }))
            }
            Expr::Cast(x, ty) => coerce(self.eval(x, row, params)?, *ty),
            Expr::Case(bs, el) => {
                for (w, t) in bs {
                    if self.eval(w, row, params)?.truthy() == Some(true) {
                        return self.eval(t, row, params);
                    }
                }
                self.eval(el, row, params)
            }
            Expr::Func(n, args) => self.function(n, args, row, params),
        }
    }
    fn function(
        &self,
        name: &str,
        args: &[Expr],
        row: &[Cell],
        params: &[Datum],
    ) -> std::result::Result<Datum, SqlError> {
        let n = name.to_ascii_lowercase();
        if n == "now" || n == "transaction_timestamp" || n == "statement_timestamp" {
            return Ok(Datum::Timestamp(chorus_common::unix_now_us()));
        }
        if n == "version" {
            return Ok(Datum::Text(
                "Chorus 0.1 (PostgreSQL 16 compatible wire)".into(),
            ));
        }
        if n == "current_database" {
            return Ok(Datum::Text("app".into()));
        }
        if n == "current_schema" {
            return Ok(Datum::Text("public".into()));
        }
        if n == "current_user" {
            return Ok(Datum::Text("app".into()));
        }
        if n == "pg_backend_pid" {
            return Ok(Datum::Int32(std::process::id() as i32));
        }
        if args.len() == 1 {
            let v = self.eval(&args[0], row, params)?;
            return Ok(match n.as_str() {
                "lower" => Datum::Text(v.display_text().to_lowercase()),
                "upper" => Datum::Text(v.display_text().to_uppercase()),
                "length" => Datum::Int32(v.display_text().chars().count() as i32),
                "octet_length" => Datum::Int32(v.display_text().len() as i32),
                "abs" => v
                    .as_i64()
                    .map(|x| Datum::Int64(x.abs()))
                    .or_else(|| v.as_f64().map(|x| Datum::Float64(x.abs())))
                    .unwrap_or(Datum::Null),
                _ => {
                    return Err(SqlError::unsupported(format!(
                        "function {name} is not supported"
                    )));
                }
            });
        }
        if args.len() == 2 {
            let a = self.eval(&args[0], row, params)?;
            let b = self.eval(&args[1], row, params)?;
            return Ok(match n.as_str() {
                "greatest" => {
                    if a >= b {
                        a
                    } else {
                        b
                    }
                }
                "least" => {
                    if a <= b {
                        a
                    } else {
                        b
                    }
                }
                "nullif" => {
                    if eval_binary(&a, BinOp::Eq, &b)?.as_bool() == Some(true) {
                        Datum::Null
                    } else {
                        a
                    }
                }
                _ => {
                    return Err(SqlError::unsupported(format!(
                        "function {name} is not supported"
                    )));
                }
            });
        }
        Err(SqlError::unsupported(format!(
            "function {name} is not supported"
        )))
    }
}

impl Statement {
    fn is_ddl(&self) -> bool {
        matches!(
            self,
            Self::CreateTable { .. }
                | Self::DropTable { .. }
                | Self::AlterTable { .. }
                | Self::CreateIndex { .. }
                | Self::DropIndex { .. }
        )
    }
    fn txn_control(&self) -> bool {
        matches!(self, Self::Begin { .. } | Self::Commit | Self::Rollback)
    }
}

#[derive(Clone)]
struct Cell {
    name: String,
    value: Datum,
}
struct Row {
    key: Vec<u8>,
    row: chorus_codec::EncodedRowV1,
    cells: Vec<Cell>,
}
fn find_table<'a>(c: &'a Catalog, n: &str) -> std::result::Result<&'a TableDescriptor, SqlError> {
    c.table_by_name(n)
        .ok_or_else(|| SqlError::new("42P01", format!("relation \"{n}\" does not exist")))
}
fn dummy_table() -> &'static TableDescriptor {
    Box::leak(Box::new(TableDescriptor {
        oid: 0,
        schema_oid: 0,
        name: "".into(),
        schema_version: 0,
        columns: Vec::new(),
        primary_key: None,
        secondary_indexes: Vec::new(),
        row_count: 0,
        state: ObjectState::Live,
    }))
}
fn cells(t: &TableDescriptor, r: &chorus_codec::EncodedRowV1) -> Vec<Cell> {
    t.columns
        .iter()
        .filter(|c| c.state == ColumnState::Live)
        .map(|c| Cell {
            name: c.name.clone(),
            value: r
                .get(c.id)
                .cloned()
                .unwrap_or_else(|| c.default.clone().unwrap_or(Datum::Null)),
        })
        .collect()
}
fn scan(tx: &Transaction, t: &TableDescriptor) -> std::result::Result<Vec<Row>, SqlError> {
    let p = [
        0x20,
        (t.oid >> 24) as u8,
        (t.oid >> 16) as u8,
        (t.oid >> 8) as u8,
        t.oid as u8,
    ];
    let end = chorus_codec::successor(&p);
    let mut out = Vec::new();
    for (key, bytes) in tx.scan(&p, end.as_deref()) {
        let row = chorus_codec::EncodedRowV1::decode(&bytes).map_err(codec_sql)?;
        out.push(Row {
            key,
            cells: cells(t, &row),
            row,
        });
    }
    Ok(out)
}
fn key_for(
    tx: &Transaction,
    t: &TableDescriptor,
    r: &chorus_codec::EncodedRowV1,
    ordinal: u32,
) -> std::result::Result<Vec<u8>, SqlError> {
    let mut out = vec![0x20];
    out.extend_from_slice(&t.oid.to_be_bytes());
    if let Some(pk) = t.primary_key {
        let v = r
            .get(pk)
            .ok_or_else(|| SqlError::new("23502", "null value in primary key"))?;
        if v.is_null() {
            return Err(SqlError::new("23502", "null value in primary key"));
        }
        out.extend(encode_composite(&[v.clone()], &[false]).map_err(codec_sql)?);
    } else {
        let mut x = tx.transaction_id.to_vec();
        x.extend_from_slice(&tx.statement_ordinal.to_be_bytes());
        x.extend_from_slice(&ordinal.to_be_bytes());
        out.extend(hash32(&x));
    }
    Ok(out)
}
fn result_column(e: &Expr, t: &TableDescriptor) -> ResultColumn {
    match e {
        Expr::Column(n) | Expr::Qualified(_, n) => t
            .columns
            .iter()
            .find(|c| c.name == *n)
            .map(|c| ResultColumn {
                name: n.clone(),
                data_type: c.data_type,
                table_oid: t.oid,
                column_oid: c.id,
            })
            .unwrap_or(ResultColumn {
                name: n.clone(),
                data_type: SqlType::Text,
                table_oid: 0,
                column_oid: 0,
            }),
        Expr::Func(n, _) => ResultColumn {
            name: n.clone(),
            data_type: if n.eq_ignore_ascii_case("count") {
                SqlType::BigInt
            } else {
                SqlType::Text
            },
            table_oid: 0,
            column_oid: 0,
        },
        _ => ResultColumn {
            name: "?column?".into(),
            data_type: SqlType::Text,
            table_oid: 0,
            column_oid: 0,
        },
    }
}
fn codec_sql(e: chorus_codec::CodecError) -> SqlError {
    SqlError::new("XX000", e.to_string())
}
fn to_sql(e: ChorusError) -> SqlError {
    match e {
        ChorusError::Sql(s) => s,
        ChorusError::Limit(s) => SqlError::new("54000", s),
        ChorusError::Consensus(s) => SqlError::cluster_unavailable(s),
        ChorusError::Storage(s)
        | ChorusError::Protocol(s)
        | ChorusError::Serialization(s)
        | ChorusError::Internal(s) => SqlError::new("XX000", s),
    }
}
fn coerce(v: Datum, ty: SqlType) -> std::result::Result<Datum, SqlError> {
    if v.is_null() {
        return Ok(v);
    }
    match (v, ty) {
        (Datum::Int16(x), SqlType::Integer) => Ok(Datum::Int32(x as i32)),
        (Datum::Int64(x), SqlType::Integer) => i32::try_from(x)
            .map(Datum::Int32)
            .map_err(|_| SqlError::new("22003", "integer out of range")),
        (Datum::Int16(x), SqlType::BigInt) => Ok(Datum::Int64(x as i64)),
        (Datum::Int32(x), SqlType::BigInt) => Ok(Datum::Int64(x as i64)),
        (Datum::Int16(x), SqlType::Double) => Ok(Datum::Float64(x as f64)),
        (Datum::Int32(x), SqlType::Double) => Ok(Datum::Float64(x as f64)),
        (Datum::Int64(x), SqlType::Double) => Ok(Datum::Float64(x as f64)),
        (Datum::Text(x), SqlType::Varchar(n))
            if n.map(|n| x.chars().count() > n as usize).unwrap_or(false) =>
        {
            Err(SqlError::new(
                "22001",
                "value too long for character varying",
            ))
        }
        (x, ty)
            if x.sql_type() == Some(ty)
                || matches!(
                    (x.sql_type(), ty),
                    (Some(SqlType::Varchar(_)), SqlType::Text)
                ) =>
        {
            Ok(x)
        }
        (x, ty) => Err(SqlError::new(
            "42804",
            format!(
                "column is of type {} but expression is of type {}",
                ty.name(),
                x.sql_type().map(SqlType::name).unwrap_or("unknown")
            ),
        )),
    }
}
fn eval_binary(a: &Datum, op: BinOp, b: &Datum) -> std::result::Result<Datum, SqlError> {
    use BinOp::*;
    if matches!(op, And | Or) {
        let x = a.truthy();
        let y = b.truthy();
        return Ok(match op {
            And => {
                if x == Some(false) || y == Some(false) {
                    Datum::Boolean(false)
                } else if x == Some(true) && y == Some(true) {
                    Datum::Boolean(true)
                } else {
                    Datum::Null
                }
            }
            Or => {
                if x == Some(true) || y == Some(true) {
                    Datum::Boolean(true)
                } else if x == Some(false) && y == Some(false) {
                    Datum::Boolean(false)
                } else {
                    Datum::Null
                }
            }
            _ => unreachable!(),
        });
    }
    if a.is_null() || b.is_null() {
        return Ok(Datum::Null);
    }
    match op {
        Eq => Ok(Datum::Boolean(a == b)),
        Ne => Ok(Datum::Boolean(a != b)),
        Lt => Ok(Datum::Boolean(a < b)),
        Le => Ok(Datum::Boolean(a <= b)),
        Gt => Ok(Datum::Boolean(a > b)),
        Ge => Ok(Datum::Boolean(a >= b)),
        Concat => Ok(Datum::Text(format!(
            "{}{}",
            a.display_text(),
            b.display_text()
        ))),
        Add | Sub | Mul | Div => {
            if let (Some(x), Some(y)) = (a.as_i64(), b.as_i64()) {
                let z = match op {
                    Add => x.checked_add(y),
                    Sub => x.checked_sub(y),
                    Mul => x.checked_mul(y),
                    Div if y != 0 => x.checked_div(y),
                    Div => return Err(SqlError::new("22012", "division by zero")),
                    _ => None,
                };
                return z
                    .map(Datum::Int64)
                    .ok_or_else(|| SqlError::new("22003", "integer out of range"));
            }
            let x = a
                .as_f64()
                .ok_or_else(|| SqlError::new("42883", "operator does not exist"))?;
            let y = b
                .as_f64()
                .ok_or_else(|| SqlError::new("42883", "operator does not exist"))?;
            Ok(Datum::Float64(match op {
                Add => x + y,
                Sub => x - y,
                Mul => x * y,
                Div if y != 0.0 => x / y,
                Div => return Err(SqlError::new("22012", "division by zero")),
                _ => unreachable!(),
            }))
        }
        _ => Err(SqlError::unsupported("operator is not supported")),
    }
}
fn like(text: &str, pattern: &str) -> bool {
    if pattern == "%" {
        return true;
    }
    let mut pos = 0;
    for (i, part) in pattern.split('%').enumerate() {
        if part.is_empty() {
            continue;
        }
        if i == 0 {
            if !text.starts_with(part) {
                return false;
            }
            pos = part.len();
        } else if let Some(n) = text[pos..].find(part) {
            pos += n + part.len();
        } else {
            return false;
        }
    }
    pattern.ends_with('%') || pos == text.len()
}
fn set_setting(s: &mut SessionSettings, n: &str, raw: &str) -> std::result::Result<(), SqlError> {
    let n = n.to_ascii_lowercase();
    let v = raw.trim().trim_matches('\'').trim_matches('"');
    match n.as_str() {
        "application_name" => s.application_name = v.into(),
        "search_path" if v == "public" || v == "public, pg_catalog" => s.search_path = v.into(),
        "client_encoding" if v.eq_ignore_ascii_case("utf8") || v.eq_ignore_ascii_case("utf-8") => {
            s.client_encoding = "UTF8".into()
        }
        "timezone" if v.eq_ignore_ascii_case("utc") => s.timezone = "UTC".into(),
        "datestyle" if v.to_ascii_uppercase().starts_with("ISO") => s.datestyle = v.into(),
        "transaction_isolation" => s.transaction_isolation = "serializable".into(),
        "transaction_read_only" => {
            s.transaction_read_only = v.eq_ignore_ascii_case("on") || v.eq_ignore_ascii_case("true")
        }
        "statement_timeout" => {
            s.statement_timeout_ms = v
                .parse()
                .map_err(|_| SqlError::new("22023", "invalid timeout"))?
        }
        "idle_in_transaction_session_timeout" => {
            s.idle_in_transaction_session_timeout_ms = v
                .parse()
                .map_err(|_| SqlError::new("22023", "invalid timeout"))?
        }
        "standard_conforming_strings" => {
            s.standard_conforming_strings = !v.eq_ignore_ascii_case("off")
        }
        "extra_float_digits" => {
            s.extra_float_digits = v
                .parse()
                .map_err(|_| SqlError::new("22023", "invalid value"))?
        }
        "bytea_output" if v.eq_ignore_ascii_case("hex") || v.eq_ignore_ascii_case("escape") => {
            s.bytea_output = v.into()
        }
        _ => {
            return Err(SqlError::unsupported(format!(
                "setting {n} is not supported"
            )));
        }
    }
    Ok(())
}

fn bind_ddl(
    s: Statement,
    snap: &StateSnapshot,
) -> std::result::Result<(SchemaOperationV1, String), SqlError> {
    let c = snap.catalog();
    match s {
        Statement::CreateTable {
            name,
            if_not_exists,
            columns,
            primary_key,
        } => {
            if let Some(t) = c.table_by_name(&name) {
                if if_not_exists {
                    return Ok((
                        SchemaOperationV1::RenameTable {
                            table_id: t.oid,
                            new_name: t.name.clone(),
                            expected_version: t.schema_version,
                        },
                        "CREATE TABLE".into(),
                    ));
                }
                return Err(SqlError::new("42P07", "relation already exists"));
            }
            let id = c.next_object_id;
            let cols: Vec<_> = columns
                .into_iter()
                .enumerate()
                .map(|(i, x)| (id + i as u32 + 1, x.name, x.ty, x.nullable, x.default))
                .collect();
            let pks = primary_key
                .into_iter()
                .map(|n| {
                    cols.iter()
                        .find(|(_, x, _, _, _)| *x == n)
                        .map(|(i, _, _, _, _)| *i)
                        .ok_or_else(|| SqlError::new("42703", "primary key column does not exist"))
                })
                .collect::<std::result::Result<Vec<_>, _>>()?;
            Ok((
                SchemaOperationV1::CreateTable {
                    table_id: id,
                    schema_id: 2200,
                    name,
                    schema_version: 1,
                    columns: cols,
                    primary_key: pks,
                },
                "CREATE TABLE".into(),
            ))
        }
        Statement::DropTable { name, if_exists } => match c.table_by_name(&name) {
            Some(t) => Ok((
                SchemaOperationV1::DropTable {
                    table_id: t.oid,
                    expected_version: t.schema_version,
                },
                "DROP TABLE".into(),
            )),
            None if if_exists => Ok((
                SchemaOperationV1::DropTable {
                    table_id: 0,
                    expected_version: 0,
                },
                "DROP TABLE".into(),
            )),
            None => Err(SqlError::new("42P01", "table does not exist")),
        },
        Statement::AlterTable { table, op } => {
            let t = c
                .table_by_name(&table)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))?;
            let operation = match op {
                AlterOp::Add(x) => SchemaOperationV1::AddColumn {
                    table_id: t.oid,
                    column_id: t.columns.iter().map(|x| x.id).max().unwrap_or(0) + 1,
                    expected_version: t.schema_version,
                    name: x.name,
                    data_type: x.ty,
                    nullable: x.nullable,
                    default: x.default,
                },
                AlterOp::Drop(n) => {
                    let x = t
                        .columns
                        .iter()
                        .find(|x| x.name == n)
                        .ok_or_else(|| SqlError::new("42703", "column does not exist"))?;
                    SchemaOperationV1::DropColumn {
                        table_id: t.oid,
                        column_id: x.id,
                        expected_version: t.schema_version,
                    }
                }
                AlterOp::RenameTable(n) => SchemaOperationV1::RenameTable {
                    table_id: t.oid,
                    new_name: n,
                    expected_version: t.schema_version,
                },
                AlterOp::RenameColumn(a, b) => {
                    let x = t
                        .columns
                        .iter()
                        .find(|x| x.name == a)
                        .ok_or_else(|| SqlError::new("42703", "column does not exist"))?;
                    SchemaOperationV1::RenameColumn {
                        table_id: t.oid,
                        column_id: x.id,
                        new_name: b,
                        expected_version: t.schema_version,
                    }
                }
            };
            Ok((operation, "ALTER TABLE".into()))
        }
        Statement::CreateIndex {
            name,
            table,
            unique,
            if_not_exists,
            columns,
        } => {
            if let Some(i) = c.index_by_name(&name) {
                if if_not_exists {
                    return Ok((
                        SchemaOperationV1::DropIndex {
                            index_id: i.oid,
                            expected_table_version: 0,
                        },
                        "CREATE INDEX".into(),
                    ));
                }
                return Err(SqlError::new("42P07", "relation already exists"));
            }
            let t = c
                .table_by_name(&table)
                .ok_or_else(|| SqlError::new("42P01", "table does not exist"))?;
            let cols = columns
                .into_iter()
                .map(|(n, d)| {
                    let x = t
                        .columns
                        .iter()
                        .find(|x| x.name == n)
                        .ok_or_else(|| SqlError::new("42703", "column does not exist"))?;
                    Ok((x.id, d))
                })
                .collect::<std::result::Result<Vec<_>, SqlError>>()?;
            Ok((
                SchemaOperationV1::CreateIndex {
                    index_id: c.next_object_id + 1,
                    table_id: t.oid,
                    name,
                    unique,
                    columns: cols,
                },
                if unique {
                    "CREATE UNIQUE INDEX"
                } else {
                    "CREATE INDEX"
                }
                .into(),
            ))
        }
        Statement::DropIndex { name, if_exists } => match c.index_by_name(&name) {
            Some(i) => {
                let t = c
                    .table(i.table_oid)
                    .ok_or_else(|| SqlError::new("42P01", "table does not exist"))?;
                Ok((
                    SchemaOperationV1::DropIndex {
                        index_id: i.oid,
                        expected_table_version: t.schema_version,
                    },
                    "DROP INDEX".into(),
                ))
            }
            None if if_exists => Ok((
                SchemaOperationV1::DropIndex {
                    index_id: 0,
                    expected_table_version: 0,
                },
                "DROP INDEX".into(),
            )),
            None => Err(SqlError::new("42704", "index does not exist")),
        },
        _ => Err(SqlError::unsupported("not a schema statement")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chorus_storage::MemoryStateStore;
    use chorus_txn::LocalCommitter;
    #[test]
    fn crud() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
        let o = OriginId::new(1);
        let c: Arc<dyn Committer> = Arc::new(LocalCommitter::new(store.clone(), o).unwrap());
        let e = SqlEngine::new(store, c, Limits::default());
        let mut s = e.session();
        s.execute(
            "CREATE TABLE users (id integer, name text, primary key (id));",
            &[],
        )
        .unwrap();
        s.execute("INSERT INTO users (id,name) VALUES (1,'Ada');", &[])
            .unwrap();
        let r = s
            .execute("SELECT id,name FROM users WHERE id = 1;", &[])
            .unwrap();
        assert_eq!(r.rows.len(), 1);
    }
    #[test]
    fn parser_values() {
        let x = Parser::batch("SELECT 1 + 2").unwrap();
        assert_eq!(x.len(), 1);
    }
}
