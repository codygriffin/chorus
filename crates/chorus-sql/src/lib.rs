#![forbid(unsafe_code)]

//! SQL parser, binder and executor for the documented Chorus MVP subset.
//! The implementation is intentionally deterministic and keeps parser types
//! private to this crate.

use chorus_codec::{ApplyResult, SchemaOperationV1, encode_composite, hash32};
#[cfg(test)]
use chorus_common::OriginId;
use chorus_common::{ChorusError, Datum, Limits, SqlError, SqlType, unix_now_us};
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
    sequencer: Arc<CommitSequencer>,
}
impl SqlEngine {
    pub fn new(
        store: Arc<dyn StateStore>,
        committer: Arc<dyn Committer>,
        limits: Limits,
    ) -> Arc<Self> {
        let sequencer = Arc::new(CommitSequencer::new(committer.origin()));
        Arc::new(Self {
            store,
            committer,
            limits,
            sequencer,
        })
    }
    pub fn session(self: &Arc<Self>) -> SqlSession {
        SqlSession {
            engine: Arc::clone(self),
            txn: None,
            failed: false,
            settings: SessionSettings::default(),
            prepared: HashMap::new(),
            sequencer: Arc::clone(&self.sequencer),
            transaction_timestamp_us: None,
            statement_timestamp_us: None,
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
    from_alias: Option<String>,
    joins: Vec<JoinSpec>,
    selection: Option<Expr>,
    group_by: Vec<Expr>,
    having: Option<Expr>,
    order: Vec<(Expr, bool)>,
    limit: Option<usize>,
    offset: usize,
    distinct: bool,
}
#[derive(Clone, Debug)]
struct JoinSpec {
    relation: String,
    alias: Option<String>,
    kind: JoinKind,
    on: Expr,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum JoinKind {
    Inner,
    Left,
}
#[derive(Clone, Debug)]
struct Insert {
    table: String,
    columns: Vec<String>,
    values: Vec<Vec<Expr>>,
    returning: Vec<Expr>,
    conflict_nothing: bool,
    conflict_update: Vec<(String, Expr)>,
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
    JsonGet,
    JsonText,
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
                '+' | '-' | '/' | '=' | '<' | '>' | '!' | '|' | ':' => {
                    out.push(Tok::Op(self.operator()))
                }
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
                ('<', '=')
                    | ('>', '=')
                    | ('<', '>')
                    | ('!', '=')
                    | ('|', '|')
                    | (':', ':')
                    | ('-', '>')
            )
        {
            self.p += 1;
            if self.chars[s] == '-'
                && self.chars.get(self.p - 1) == Some(&'>')
                && self.chars.get(self.p) == Some(&'>')
            {
                self.p += 1;
            }
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
            "reset" => Ok(Statement::Set(self.take_word()?, "default".into())),
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
                let name = self.relation_name()?;
                self.word("as")?;
                Ok(Statement::Prepare {
                    name,
                    sql: self.rest_text(),
                })
            }
            "execute" => {
                let name = self.relation_name()?;
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
                let name = self.relation_name()?;
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
                let table = self.relation_name()?;
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
        let name = self.relation_name()?;
        Ok(match k.as_str() {
            "table" => Statement::DropTable { name, if_exists },
            "index" => Statement::DropIndex { name, if_exists },
            _ => Statement::Unsupported(format!("DROP {k} is not supported")),
        })
    }
    fn alter_stmt(&mut self) -> std::result::Result<Statement, SqlError> {
        self.word("table")?;
        let table = self.relation_name()?;
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
            let expression = if self.eat(Tok::Star) {
                Expr::Star
            } else {
                self.expr()?
            };
            // Column aliases affect presentation, not expression semantics.
            // Keep the compact AST while accepting the form emitted by psql
            // and most PostgreSQL drivers.
            if self.eat_word("as") {
                let _ = self.take_word()?;
            }
            projection.push(expression);
            if !self.eat(Tok::Comma) {
                break;
            }
        }
        let mut from_alias = None;
        let from = if values_only {
            None
        } else if self.eat_word("from") {
            let relation = self.relation_name()?;
            if self.eat_word("as") {
                from_alias = Some(self.take_word()?);
            } else if self.peek_word_not_clause() {
                // A bare alias is unambiguous at this position.  JOIN is
                // intentionally left for the unsupported-feature path.
                from_alias = Some(self.take_word()?);
            }
            Some(relation)
        } else {
            None
        };
        let mut joins = Vec::new();
        if from.is_some() {
            loop {
                let save = self.p;
                let kind = if self.eat_word("left") {
                    self.eat_word("outer");
                    if !self.eat_word("join") {
                        self.p = save;
                        break;
                    }
                    JoinKind::Left
                } else if self.eat_word("inner") {
                    if !self.eat_word("join") {
                        self.p = save;
                        break;
                    }
                    JoinKind::Inner
                } else if self.eat_word("join") {
                    JoinKind::Inner
                } else {
                    break;
                };
                let relation = self.relation_name()?;
                let mut alias = None;
                if self.eat_word("as") {
                    alias = Some(self.take_word()?);
                } else if self.peek_word_not_clause() {
                    alias = Some(self.take_word()?);
                }
                self.word("on")?;
                joins.push(JoinSpec {
                    relation,
                    alias,
                    kind,
                    on: self.expr()?,
                });
            }
        }
        let mut selection = None;
        let mut group_by = Vec::new();
        let mut having = None;
        let mut order = Vec::new();
        let mut limit = None;
        let mut offset = 0;
        while self.p < self.t.len() {
            if self.eat_word("where") {
                selection = Some(self.expr()?);
            } else if self.eat_word("group") {
                self.word("by")?;
                group_by = self.expr_list()?;
            } else if self.eat_word("having") {
                having = Some(self.expr()?);
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
            from_alias,
            joins,
            selection,
            group_by,
            having,
            order,
            limit,
            offset,
            distinct,
        }))
    }
    fn insert_stmt(&mut self) -> std::result::Result<Statement, SqlError> {
        self.word("into")?;
        let table = self.relation_name()?;
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
        let mut conflict_nothing = false;
        let mut conflict_update = Vec::new();
        if self.words(&["on", "conflict"]) {
            if self.eat(Tok::L) {
                self.names_close()?;
            }
            self.word("do")?;
            if self.eat_word("nothing") {
                conflict_nothing = true;
            } else {
                self.word("update")?;
                self.word("set")?;
                loop {
                    let name = self.take_word()?;
                    self.expect_op("=")?;
                    conflict_update.push((name, self.expr()?));
                    if !self.eat(Tok::Comma) {
                        break;
                    }
                }
            }
        }
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
            conflict_update,
        }))
    }
    fn update_stmt(&mut self) -> std::result::Result<Statement, SqlError> {
        let table = self.relation_name()?;
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
        let table = self.relation_name()?;
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
            Some(Tok::Word(w)) if w == "current_date" => Ok(Some(Datum::Date(
                unix_now_us().div_euclid(86_400_000_000) as i32,
            ))),
            Some(Tok::Word(w)) if w == "current_timestamp" || w == "now" => {
                Ok(Some(Datum::Timestamp(unix_now_us())))
            }
            Some(Tok::Word(w)) if w == "date" || w == "timestamp" || w == "timestamptz" => {
                let text = match self.next() {
                    Some(Tok::Str(value)) => value,
                    other => {
                        return Err(SqlError::new(
                            "42601",
                            format!("expected temporal literal, got {other:?}"),
                        ));
                    }
                };
                Ok(Some(parse_temporal_literal(&w, &text)?))
            }
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
                let temporal_start = self.p;
                let temporal_kind = if w == "timestamp" && self.words(&["with", "time", "zone"]) {
                    Some("timestamptz")
                } else if matches!(w.as_str(), "date" | "timestamp" | "timestamptz") {
                    Some(w.as_str())
                } else {
                    None
                };
                if let Some(kind) = temporal_kind {
                    if let Some(Tok::Str(value)) = self.next() {
                        Expr::Literal(parse_temporal_literal(kind, &value)?)
                    } else {
                        self.p = temporal_start;
                        Expr::Column(w)
                    }
                } else if matches!(
                    w.as_str(),
                    "current_date" | "current_timestamp" | "localtimestamp"
                ) {
                    Expr::Func(w, Vec::new())
                } else if self.eat(Tok::L) {
                    if w == "cast" {
                        let value = self.expr()?;
                        self.word("as")?;
                        let ty = self.ty()?;
                        self.expect(Tok::R)?;
                        Expr::Cast(Box::new(value), ty)
                    } else {
                        let mut args = Vec::new();
                        if !self.eat(Tok::R) {
                            args = self.expr_list()?;
                            self.expect(Tok::R)?;
                        }
                        Expr::Func(w, args)
                    }
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
            if self.eat_op("::") {
                e = Expr::Cast(Box::new(e), self.ty()?);
            } else if self.eat_word("is") { let not = self.eat_word("not"); self.word("null")?; e = Expr::IsNull(Box::new(e), not); } else if self.peek_word("in") || self.peek_word("between") || self.peek_word("like") || (self.peek_word("not") && self.t.get(self.p + 1).map(|t| matches!(t, Tok::Word(w) if w == "in" || w == "between" || w == "like")).unwrap_or(false)) { let not = self.eat_word("not"); if self.eat_word("in") { self.expect(Tok::L)?; let mut v = Vec::new(); loop { v.push(self.expr()?); if self.eat(Tok::R) { break; } self.expect(Tok::Comma)?; } e = Expr::In(Box::new(e), v, not); } else if self.eat_word("between") { let lo = self.expr()?; self.word("and")?; let hi = self.expr()?; e = Expr::Between(Box::new(e), Box::new(lo), Box::new(hi), not); } else { self.word("like")?; e = Expr::Like(Box::new(e), Box::new(self.primary()?), not); } } else { break; }
        }
        Ok(e)
    }
    fn case_expr(&mut self) -> std::result::Result<Expr, SqlError> {
        let mut b = Vec::new();
        let base = if self.peek_word("when") {
            None
        } else {
            Some(self.expr()?)
        };
        while self.eat_word("when") {
            let condition = self.expr()?;
            let w = if let Some(base) = &base {
                Expr::Binary(Box::new(base.clone()), BinOp::Eq, Box::new(condition))
            } else {
                condition
            };
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
                "->" => (BinOp::JsonGet, 4),
                "->>" => (BinOp::JsonText, 4),
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
    fn relation_name(&mut self) -> std::result::Result<String, SqlError> {
        let mut name = self.take_word()?;
        while self.eat(Tok::Dot) {
            name.push('.');
            name.push_str(&self.take_word()?);
        }
        Ok(name)
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
    fn peek_word_not_clause(&self) -> bool {
        matches!(self.peek(), Some(Tok::Word(x)) if !matches!(x.as_str(), "where" | "order" | "limit" | "offset" | "group" | "having" | "join" | "left" | "right" | "inner" | "on"))
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
    transaction_timestamp_us: Option<i64>,
    statement_timestamp_us: Option<i64>,
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
    pub fn close_prepared(&mut self, name: &str) {
        self.prepared.remove(name);
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
                    } else if self.txn.is_some() && e.code != "25P02" && e.code != "08006" {
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
        if Parser::batch(sql)?.len() != 1 {
            return Err(SqlError::new(
                "42601",
                "prepared statements must contain exactly one SQL statement",
            ));
        }
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
        if self.failed && !matches!(s, Statement::Commit | Statement::Rollback) {
            return Err(SqlError::failed_transaction());
        }
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
        let transaction = Transaction::begin(snapshot, self.engine.limits.clone());
        self.transaction_timestamp_us = Some(transaction.transaction_timestamp_us);
        self.statement_timestamp_us = Some(transaction.statement_timestamp_us);
        self.txn = Some(transaction);
        self.failed = false;
        Ok(())
    }
    fn commit_internal(&mut self) -> std::result::Result<(), SqlError> {
        if let Some(mut txn) = self.txn.take() {
            let r = match txn.commit(self.engine.committer.as_ref(), &self.sequencer) {
                Ok(result) => result,
                Err(error @ ChorusError::Consensus(_)) => {
                    // The transport outcome may be ambiguous. Preserve the
                    // transaction overlay and exact sequencer request so a
                    // client can retry COMMIT without rebuilding a different
                    // mutation batch or reusing a sequence number.
                    self.txn = Some(txn);
                    return Err(to_sql(error));
                }
                Err(error) => return Err(to_sql(error)),
            };
            if matches!(r, ApplyResult::SerializationFailure { .. }) {
                return Err(SqlError::serialization(
                    "could not serialize access due to concurrent update",
                ));
            }
        }
        self.failed = false;
        self.transaction_timestamp_us = None;
        self.statement_timestamp_us = None;
        Ok(())
    }
    fn rollback_internal(&mut self) {
        if let Some(t) = self.txn.as_mut() {
            t.rollback();
        }
        self.txn = None;
        self.failed = false;
        self.transaction_timestamp_us = None;
        self.statement_timestamp_us = None;
    }
    fn prepare_statement(&mut self, tx: &mut Transaction) -> std::result::Result<(), SqlError> {
        tx.check_age().map_err(to_sql)?;
        tx.set_statement_time().map_err(to_sql)?;
        self.statement_timestamp_us = Some(tx.statement_timestamp_us);
        Ok(())
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
        // IF [NOT] EXISTS branches are true no-ops.  They must not consume a
        // catalog epoch or manufacture a fake schema command, because doing
        // so would make two replicas disagree about whether a DDL statement
        // changed logical state.
        match &s {
            Statement::CreateTable {
                name,
                if_not_exists: true,
                ..
            } if snap.catalog().table_by_name(relation_leaf(name)).is_some() => {
                return Ok(QueryResult::command("CREATE TABLE", 0));
            }
            Statement::CreateIndex {
                name,
                if_not_exists: true,
                ..
            } if snap.catalog().index_by_name(relation_leaf(name)).is_some() => {
                return Ok(QueryResult::command("CREATE INDEX", 0));
            }
            Statement::DropTable {
                name,
                if_exists: true,
            } if snap.catalog().table_by_name(relation_leaf(name)).is_none() => {
                return Ok(QueryResult::command("DROP TABLE", 0));
            }
            Statement::DropIndex {
                name,
                if_exists: true,
            } if snap.catalog().index_by_name(relation_leaf(name)).is_none() => {
                return Ok(QueryResult::command("DROP INDEX", 0));
            }
            _ => {}
        }
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
        if let Err(error) = self.prepare_statement(&mut tx) {
            self.txn = Some(tx);
            return Err(error);
        }
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
        tx.check_age().map_err(to_sql)?;
        if q.from
            .as_deref()
            .is_some_and(|name| is_virtual_relation(name))
        {
            return self.select_virtual(tx, q, params);
        }
        let table = q
            .from
            .as_ref()
            .map(|n| find_table(tx.snapshot.catalog(), n))
            .transpose()?
            .cloned();
        if let Some(table) = table {
            let mut rows = scan(tx, &table)?;
            if !q.joins.is_empty() {
                rows =
                    self.join_rows(tx, &table, q.from_alias.as_deref(), rows, &q.joins, params)?;
            }
            if let Some(w) = &q.selection {
                let mut filtered = Vec::with_capacity(rows.len());
                for row in rows {
                    if self.eval(w, &row.cells, params)?.truthy() == Some(true) {
                        filtered.push(row);
                    }
                }
                rows = filtered;
            }
            if !q.group_by.is_empty()
                || q.projection.iter().any(has_aggregate)
                || q.having.as_ref().is_some_and(has_aggregate)
            {
                return self.select_grouped(&table, rows, q, params);
            }
            for (e, desc) in q.order.iter().rev() {
                let mut keyed = Vec::with_capacity(rows.len());
                for row in rows {
                    let key = self.eval(e, &row.cells, params)?;
                    keyed.push((row, key));
                }
                keyed.sort_by(|(_, x), (_, y)| {
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
                rows = keyed.into_iter().map(|(row, _)| row).collect();
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

    fn select_grouped(
        &self,
        table: &TableDescriptor,
        rows: Vec<Row>,
        q: Select,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        let mut groups: Vec<(Vec<Datum>, Vec<Row>)> = Vec::new();
        for row in rows {
            let key = q
                .group_by
                .iter()
                .map(|expr| self.eval(expr, &row.cells, params))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if let Some((_, group)) = groups.iter_mut().find(|(old, _)| *old == key) {
                group.push(row);
            } else {
                groups.push((key, vec![row]));
            }
        }
        // An aggregate without GROUP BY still produces one row for an empty
        // input (COUNT(*) = 0, other aggregates = NULL).
        if groups.is_empty() && q.group_by.is_empty() {
            groups.push((Vec::new(), Vec::new()));
        }
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
        let columns = projection.iter().map(|e| result_column(e, table)).collect();
        let mut out = Vec::new();
        for (_, group) in groups {
            if let Some(having) = &q.having {
                if self.eval_group(having, &group, params)?.truthy() != Some(true) {
                    continue;
                }
            }
            let row = projection
                .iter()
                .map(|expr| self.eval_group(expr, &group, params))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if q.distinct && out.iter().any(|old: &Vec<Datum>| old == &row) {
                continue;
            }
            out.push(row);
        }
        Ok(QueryResult {
            affected_rows: out.len() as u64,
            rows: out,
            columns,
            command_tag: "SELECT".into(),
            notices: Vec::new(),
        })
    }

    fn eval_group(
        &self,
        expr: &Expr,
        group: &[Row],
        params: &[Datum],
    ) -> std::result::Result<Datum, SqlError> {
        if let Expr::Func(name, args) = expr {
            let n = name.to_ascii_lowercase();
            if matches!(n.as_str(), "count" | "sum" | "avg" | "min" | "max") {
                return aggregate_value(self, &n, args, group, params);
            }
        }
        match expr {
            Expr::Func(name, args) if name.eq_ignore_ascii_case("count") => {
                aggregate_value(self, "count", args, group, params)
            }
            Expr::Func(_, _) if !has_aggregate(expr) => group
                .first()
                .map(|row| self.eval(expr, &row.cells, params))
                .unwrap_or(Ok(Datum::Null)),
            Expr::Column(_) | Expr::Qualified(_, _) | Expr::Param(_) | Expr::Literal(_) => group
                .first()
                .map(|row| self.eval(expr, &row.cells, params))
                .unwrap_or(Ok(Datum::Null)),
            Expr::Binary(a, op, b) => Ok(eval_binary(
                &self.eval_group(a, group, params)?,
                *op,
                &self.eval_group(b, group, params)?,
            )?),
            Expr::Unary(op, x) => self.eval_group(x, group, params).map(|v| match op {
                Unary::Not => v
                    .as_bool()
                    .map(|b| Datum::Boolean(!b))
                    .unwrap_or(Datum::Null),
                Unary::Neg => v
                    .as_f64()
                    .map(|x| Datum::Float64(-x))
                    .unwrap_or(Datum::Null),
            }),
            Expr::IsNull(x, not) => Ok(Datum::Boolean(
                self.eval_group(x, group, params)?.is_null() ^ *not,
            )),
            Expr::Case(branches, otherwise) => {
                for (when, then) in branches {
                    if self.eval_group(when, group, params)?.truthy() == Some(true) {
                        return self.eval_group(then, group, params);
                    }
                }
                self.eval_group(otherwise, group, params)
            }
            _ => Ok(Datum::Null),
        }
    }

    fn join_rows(
        &self,
        tx: &Transaction,
        base: &TableDescriptor,
        base_alias: Option<&str>,
        rows: Vec<Row>,
        joins: &[JoinSpec],
        params: &[Datum],
    ) -> std::result::Result<Vec<Row>, SqlError> {
        let mut current = rows;
        for join in joins {
            let right = find_table(tx.snapshot.catalog(), &join.relation)?.clone();
            let right_rows = scan(tx, &right)?;
            let mut next = Vec::new();
            for left in current {
                let mut matched = false;
                for candidate in &right_rows {
                    let mut cells = left.cells.clone();
                    cells.extend(candidate.cells.iter().cloned().map(|mut cell| {
                        cell.qualifier = Some(join.alias.as_deref().unwrap_or(&right.name).into());
                        cell
                    }));
                    // Base rows carry their relation name for qualified ON
                    // expressions; unqualified expressions still resolve as
                    // PostgreSQL's binder would for this compact executor.
                    for cell in &mut cells {
                        if cell.qualifier.is_none() {
                            cell.qualifier = Some(base_alias.unwrap_or(&base.name).to_string());
                        }
                    }
                    if self.eval(&join.on, &cells, params)?.truthy() == Some(true) {
                        matched = true;
                        next.push(Row {
                            key: left.key.clone(),
                            row: left.row.clone(),
                            cells,
                        });
                    }
                }
                if !matched && join.kind == JoinKind::Left {
                    let mut cells = left.cells.clone();
                    for column in right
                        .columns
                        .iter()
                        .filter(|c| c.state == ColumnState::Live)
                    {
                        cells.push(Cell {
                            name: column.name.clone(),
                            qualifier: Some(join.alias.as_deref().unwrap_or(&right.name).into()),
                            value: Datum::Null,
                        });
                    }
                    for cell in &mut cells {
                        if cell.qualifier.is_none() {
                            cell.qualifier = Some(base_alias.unwrap_or(&base.name).to_string());
                        }
                    }
                    next.push(Row {
                        key: left.key,
                        row: left.row,
                        cells,
                    });
                }
            }
            current = next;
        }
        Ok(current)
    }

    fn select_virtual(
        &self,
        tx: &Transaction,
        q: Select,
        params: &[Datum],
    ) -> std::result::Result<QueryResult, SqlError> {
        let relation = q.from.as_deref().unwrap_or_default();
        let (columns, values) =
            virtual_relation(relation, tx.snapshot.catalog()).ok_or_else(|| {
                SqlError::new("42P01", format!("relation \"{relation}\" does not exist"))
            })?;
        let table = virtual_table(relation, &columns);
        let mut rows = values
            .into_iter()
            .map(|values| VirtualRow {
                cells: columns
                    .iter()
                    .zip(values)
                    .map(|((name, _), value)| Cell {
                        name: name.clone(),
                        qualifier: None,
                        value,
                    })
                    .collect(),
            })
            .collect::<Vec<_>>();
        if let Some(w) = &q.selection {
            let mut filtered = Vec::with_capacity(rows.len());
            for row in rows {
                if self.eval(w, &row.cells, params)?.truthy() == Some(true) {
                    filtered.push(row);
                }
            }
            rows = filtered;
        }
        for (e, desc) in q.order.iter().rev() {
            let mut keyed = Vec::with_capacity(rows.len());
            for row in rows {
                let key = self.eval(e, &row.cells, params)?;
                keyed.push((row, key));
            }
            keyed.sort_by(|(_, x), (_, y)| {
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
            rows = keyed.into_iter().map(|(row, _)| row).collect();
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
                .map(|c| Expr::Column(c.name.clone()))
                .collect::<Vec<_>>()
        } else {
            q.projection
        };
        let result_columns = projection
            .iter()
            .map(|e| result_column(e, &table))
            .collect();
        let mut out = Vec::new();
        for row in rows {
            let projected = projection
                .iter()
                .map(|e| self.eval(e, &row.cells, params))
                .collect::<std::result::Result<Vec<_>, _>>()?;
            if q.distinct && out.iter().any(|old: &Vec<Datum>| old == &projected) {
                continue;
            }
            out.push(projected);
        }
        Ok(QueryResult {
            columns: result_columns,
            affected_rows: out.len() as u64,
            rows: out,
            command_tag: "SELECT".into(),
            notices: Vec::new(),
        })
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
        if let Err(error) = self.prepare_statement(&mut tx) {
            self.txn = Some(tx);
            return Err(error);
        }
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
        tx.check_age().map_err(to_sql)?;
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
                    let v = coerce(c.default.clone().unwrap_or(Datum::Null), c.data_type)?;
                    fields.push((c.id, v));
                }
            }
            validate_fields(&table, &fields)?;
            let row =
                chorus_codec::EncodedRowV1::new(table.schema_version, fields).map_err(codec_sql)?;
            let key = key_for(tx, &table, &row, i as u32)?;
            let new_index_entries = index_entries(tx.snapshot.catalog(), &table, &row, &key)?;
            let conflict_key = if tx.get(&key).is_some() {
                Some(key.clone())
            } else {
                scan(tx, &table)?.into_iter().find_map(|candidate| {
                    let candidate_indexes = index_entries(
                        tx.snapshot.catalog(),
                        &table,
                        &candidate.row,
                        &candidate.key,
                    )
                    .ok()?;
                    if new_index_entries.iter().any(|(entry, unique)| {
                        *unique
                            && candidate_indexes
                                .iter()
                                .any(|(other, other_unique)| *other_unique && other == entry)
                    }) {
                        Some(candidate.key)
                    } else {
                        None
                    }
                })
            };
            if conflict_key.is_some()
                || new_index_entries
                    .iter()
                    .any(|(entry, unique)| *unique && tx.get(entry).is_some())
            {
                if q.conflict_nothing {
                    continue;
                }
                if !q.conflict_update.is_empty() {
                    let existing_key = conflict_key
                        .or_else(|| {
                            new_index_entries.iter().find_map(|(entry, unique)| {
                                (*unique && tx.get(entry).is_some()).then(|| key.clone())
                            })
                        })
                        .ok_or_else(|| SqlError::new("23505", "conflict row disappeared"))?;
                    let old_bytes = tx
                        .get(&existing_key)
                        .ok_or_else(|| SqlError::new("23505", "conflict row disappeared"))?;
                    let old_row =
                        chorus_codec::EncodedRowV1::decode(&old_bytes).map_err(codec_sql)?;
                    let old_cells = cells(&table, &old_row);
                    let mut eval_cells = old_cells.clone();
                    eval_cells.extend(cells(&table, &row).into_iter().map(|mut cell| {
                        cell.qualifier = Some("excluded".into());
                        cell
                    }));
                    let mut replacement = old_row.clone();
                    for (name, expression) in &q.conflict_update {
                        let column = table
                            .columns
                            .iter()
                            .find(|column| {
                                column.name == *name && column.state == ColumnState::Live
                            })
                            .ok_or_else(|| {
                                SqlError::new("42703", format!("column {name} does not exist"))
                            })?;
                        let value = coerce(
                            self.eval(expression, &eval_cells, params)?,
                            column.data_type,
                        )?;
                        if let Some(field) = replacement
                            .fields
                            .iter_mut()
                            .find(|(id, _)| *id == column.id)
                        {
                            field.1 = value;
                        } else {
                            replacement.fields.push((column.id, value));
                        }
                    }
                    replacement.fields.sort_by_key(|(id, _)| *id);
                    tx.delete(existing_key.clone()).map_err(to_sql)?;
                    for (entry, _) in
                        index_entries(tx.snapshot.catalog(), &table, &old_row, &existing_key)?
                    {
                        tx.delete(entry).map_err(to_sql)?;
                    }
                    let replacement_key = if table.primary_key.is_none() {
                        existing_key
                    } else {
                        key_for(tx, &table, &replacement, i as u32)?
                    };
                    let replacement_indexes = index_entries(
                        tx.snapshot.catalog(),
                        &table,
                        &replacement,
                        &replacement_key,
                    )?;
                    if tx.get(&replacement_key).is_some()
                        || replacement_indexes
                            .iter()
                            .any(|(entry, unique)| *unique && tx.get(entry).is_some())
                    {
                        return Err(SqlError::new(
                            "23505",
                            "duplicate key value violates unique constraint",
                        ));
                    }
                    validate_fields(&table, &replacement.fields)?;
                    tx.put(replacement_key, encode_row_checked(tx, &replacement)?)
                        .map_err(to_sql)?;
                    for (entry, _) in replacement_indexes {
                        tx.put(entry, Vec::new()).map_err(to_sql)?;
                    }
                    count += 1;
                    if !q.returning.is_empty() {
                        self.push_returning(&mut ret, &q.returning, &table, &replacement, params)?;
                    }
                    continue;
                }
                return Err(SqlError::new(
                    "23505",
                    "duplicate key value violates unique constraint",
                ));
            }
            tx.put(key.clone(), encode_row_checked(tx, &row)?)
                .map_err(to_sql)?;
            for (entry, _) in new_index_entries {
                tx.put(entry, Vec::new()).map_err(to_sql)?;
            }
            count += 1;
            if !q.returning.is_empty() {
                self.push_returning(&mut ret, &q.returning, &table, &row, params)?;
            }
        }
        Ok(QueryResult {
            columns: q
                .returning
                .iter()
                .flat_map(|e| returning_columns(e, &table))
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
        if let Err(error) = self.prepare_statement(&mut tx) {
            self.txn = Some(tx);
            return Err(error);
        }
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
        tx.check_age().map_err(to_sql)?;
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
            validate_fields(&table, &row.fields)?;
            // Remove the old row and all of its index entries before checking
            // the replacement.  This makes UPDATE of a unique key behave as
            // PostgreSQL does when the value is unchanged.
            tx.delete(target.key.clone()).map_err(to_sql)?;
            for (entry, _) in
                index_entries(tx.snapshot.catalog(), &table, &target.row, &target.key)?
            {
                tx.delete(entry).map_err(to_sql)?;
            }
            let new_key = if table.primary_key.is_none() {
                target.key.clone()
            } else {
                key_for(tx, &table, &row, count as u32)?
            };
            if tx.get(&new_key).is_some() {
                return Err(SqlError::new(
                    "23505",
                    "duplicate key value violates unique constraint",
                ));
            }
            let new_indexes = index_entries(tx.snapshot.catalog(), &table, &row, &new_key)?;
            if new_indexes
                .iter()
                .any(|(entry, unique)| *unique && tx.get(entry).is_some())
            {
                return Err(SqlError::new(
                    "23505",
                    "duplicate key value violates unique constraint",
                ));
            }
            tx.put(new_key, encode_row_checked(tx, &row)?)
                .map_err(to_sql)?;
            for (entry, _) in new_indexes {
                tx.put(entry, Vec::new()).map_err(to_sql)?;
            }
            if !q.returning.is_empty() {
                self.push_returning(&mut ret, &q.returning, &table, &row, params)?;
            }
            count += 1;
        }
        Ok(QueryResult {
            columns: q
                .returning
                .iter()
                .flat_map(|e| returning_columns(e, &table))
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
        if let Err(error) = self.prepare_statement(&mut tx) {
            self.txn = Some(tx);
            return Err(error);
        }
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
        tx.check_age().map_err(to_sql)?;
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
                self.push_returning(&mut ret, &q.returning, &table, &target.row, params)?;
            }
            tx.delete(target.key.clone()).map_err(to_sql)?;
            for (entry, _) in
                index_entries(tx.snapshot.catalog(), &table, &target.row, &target.key)?
            {
                tx.delete(entry).map_err(to_sql)?;
            }
            count += 1;
        }
        Ok(QueryResult {
            columns: q
                .returning
                .iter()
                .flat_map(|e| returning_columns(e, &table))
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
        let mut out = Vec::new();
        for expr in exprs {
            if matches!(expr, Expr::Star) {
                out.extend(cs.iter().map(|cell| cell.value.clone()));
            } else {
                out.push(self.eval(expr, &cs, params)?);
            }
        }
        Ok(out)
    }
    fn push_returning(
        &self,
        rows: &mut Vec<Vec<Datum>>,
        exprs: &[Expr],
        table: &TableDescriptor,
        row: &chorus_codec::EncodedRowV1,
        params: &[Datum],
    ) -> std::result::Result<(), SqlError> {
        let values = self.returning(exprs, table, row, params)?;
        let bytes = rows
            .iter()
            .map(|old| old.iter().map(datum_size).sum::<usize>())
            .sum::<usize>()
            .checked_add(values.iter().map(datum_size).sum::<usize>())
            .ok_or_else(|| SqlError::new("54000", "RETURNING result exceeds configured limit"))?;
        if bytes > self.engine.limits.max_returning_bytes {
            return Err(SqlError::new(
                "54000",
                "RETURNING result exceeds configured limit",
            ));
        }
        rows.push(values);
        Ok(())
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
            Expr::Qualified(q, n) => row
                .iter()
                .find(|c| c.qualifier.as_deref() == Some(q.as_str()) && c.name == *n)
                .or_else(|| row.iter().find(|c| c.name == *n))
                .map(|c| c.value.clone())
                .ok_or_else(|| SqlError::new("42703", format!("column {q}.{n} does not exist"))),
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
            Expr::Cast(x, ty) => cast_value(self.eval(x, row, params)?, *ty),
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
        if n == "now"
            || n == "transaction_timestamp"
            || n == "statement_timestamp"
            || n == "current_timestamp"
            || n == "localtimestamp"
        {
            let timestamp = if n == "statement_timestamp" {
                self.statement_timestamp_us
                    .or(self.transaction_timestamp_us)
                    .unwrap_or_else(chorus_common::unix_now_us)
            } else {
                self.transaction_timestamp_us
                    .unwrap_or_else(chorus_common::unix_now_us)
            };
            return Ok(Datum::Timestamp(timestamp));
        }
        if n == "current_date" {
            let timestamp = self
                .transaction_timestamp_us
                .unwrap_or_else(chorus_common::unix_now_us);
            return Ok(Datum::Date(timestamp.div_euclid(86_400_000_000) as i32));
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
        if n == "coalesce" {
            for arg in args {
                let value = self.eval(arg, row, params)?;
                if !value.is_null() {
                    return Ok(value);
                }
            }
            return Ok(Datum::Null);
        }
        if n == "format_type" {
            let value = args
                .first()
                .map(|arg| self.eval(arg, row, params))
                .transpose()?
                .and_then(|value| value.as_i64())
                .unwrap_or_default();
            let name = match value as u32 {
                16 => "boolean",
                17 => "bytea",
                20 => "bigint",
                21 => "smallint",
                23 => "integer",
                25 => "text",
                701 => "double precision",
                1043 => "character varying",
                1082 => "date",
                1114 => "timestamp without time zone",
                1184 => "timestamp with time zone",
                2950 => "uuid",
                3802 => "jsonb",
                _ => "unknown",
            };
            return Ok(Datum::Text(name.into()));
        }
        if n == "pg_get_userbyid" {
            return Ok(Datum::Text("app".into()));
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
    qualifier: Option<String>,
    value: Datum,
}
struct Row {
    key: Vec<u8>,
    row: chorus_codec::EncodedRowV1,
    cells: Vec<Cell>,
}
struct VirtualRow {
    cells: Vec<Cell>,
}

fn is_virtual_relation(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "pg_catalog.pg_namespace"
            | "pg_catalog.pg_class"
            | "pg_catalog.pg_attribute"
            | "pg_catalog.pg_type"
            | "pg_catalog.pg_index"
            | "pg_catalog.pg_constraint"
            | "pg_catalog.pg_database"
            | "pg_catalog.pg_roles"
            | "information_schema.tables"
            | "information_schema.columns"
    )
}

fn has_aggregate(expr: &Expr) -> bool {
    match expr {
        Expr::Func(name, args) => {
            matches!(
                name.to_ascii_lowercase().as_str(),
                "count" | "sum" | "avg" | "min" | "max"
            ) || args.iter().any(has_aggregate)
        }
        Expr::Unary(_, x) | Expr::IsNull(x, _) | Expr::Cast(x, _) => has_aggregate(x),
        Expr::Binary(a, _, b) => has_aggregate(a) || has_aggregate(b),
        Expr::In(x, xs, _) => has_aggregate(x) || xs.iter().any(has_aggregate),
        Expr::Between(x, lo, hi, _) => has_aggregate(x) || has_aggregate(lo) || has_aggregate(hi),
        Expr::Like(x, p, _) => has_aggregate(x) || has_aggregate(p),
        Expr::Case(branches, otherwise) => {
            branches
                .iter()
                .any(|(when, then)| has_aggregate(when) || has_aggregate(then))
                || has_aggregate(otherwise)
        }
        _ => false,
    }
}

fn aggregate_value(
    engine: &SqlSession,
    name: &str,
    args: &[Expr],
    group: &[Row],
    params: &[Datum],
) -> std::result::Result<Datum, SqlError> {
    if name == "count" {
        if args.is_empty() || matches!(args.first(), Some(Expr::Star)) {
            return Ok(Datum::Int64(group.len() as i64));
        }
        let mut count = 0i64;
        for row in group {
            if !engine.eval(&args[0], &row.cells, params)?.is_null() {
                count = count
                    .checked_add(1)
                    .ok_or_else(|| SqlError::new("22003", "count out of range"))?;
            }
        }
        return Ok(Datum::Int64(count));
    }
    let arg = args
        .first()
        .ok_or_else(|| SqlError::new("42803", "aggregate requires an argument"))?;
    let mut values = Vec::new();
    for row in group {
        let value = engine.eval(arg, &row.cells, params)?;
        if !value.is_null() {
            values.push(value);
        }
    }
    if values.is_empty() {
        return Ok(Datum::Null);
    }
    match name {
        "sum" => {
            if values.iter().any(|v| matches!(v, Datum::Float64(_))) {
                let mut total = 0.0;
                for value in values {
                    total += value
                        .as_f64()
                        .ok_or_else(|| SqlError::new("42803", "SUM argument is not numeric"))?;
                }
                Ok(Datum::Float64(total))
            } else {
                let mut total = 0i64;
                for value in values {
                    total =
                        total
                            .checked_add(value.as_i64().ok_or_else(|| {
                                SqlError::new("42803", "SUM argument is not numeric")
                            })?)
                            .ok_or_else(|| SqlError::new("22003", "sum out of range"))?;
                }
                Ok(Datum::Int64(total))
            }
        }
        "avg" => {
            let total = values
                .iter()
                .map(|v| v.as_f64().unwrap_or(f64::NAN))
                .sum::<f64>();
            Ok(Datum::Float64(total / values.len() as f64))
        }
        "min" => Ok(values.into_iter().min().unwrap_or(Datum::Null)),
        "max" => Ok(values.into_iter().max().unwrap_or(Datum::Null)),
        _ => Err(SqlError::unsupported("aggregate is not supported")),
    }
}

fn virtual_table(name: &str, columns: &[(String, SqlType)]) -> TableDescriptor {
    TableDescriptor {
        oid: 0,
        schema_oid: 0,
        name: name.to_string(),
        schema_version: 1,
        columns: columns
            .iter()
            .enumerate()
            .map(|(i, (name, data_type))| ColumnDescriptor {
                id: i as u32 + 1,
                name: name.clone(),
                data_type: *data_type,
                nullable: true,
                default: None,
                state: ColumnState::Live,
            })
            .collect(),
        primary_key: None,
        secondary_indexes: Vec::new(),
        row_count: 0,
        state: ObjectState::Live,
    }
}

fn virtual_relation(
    name: &str,
    catalog: &Catalog,
) -> Option<(Vec<(String, SqlType)>, Vec<Vec<Datum>>)> {
    let name = name.to_ascii_lowercase();
    let i32t = SqlType::Integer;
    let text = SqlType::Text;
    let boolt = SqlType::Boolean;
    let f64t = SqlType::Double;
    let i16t = SqlType::SmallInt;
    match name.as_str() {
        "pg_catalog.pg_namespace" => Some((
            vec![
                ("oid".into(), i32t),
                ("nspname".into(), text),
                ("nspowner".into(), i32t),
            ],
            vec![
                vec![
                    Datum::Int32(11),
                    Datum::Text("pg_catalog".into()),
                    Datum::Int32(10),
                ],
                vec![
                    Datum::Int32(2200),
                    Datum::Text("public".into()),
                    Datum::Int32(10),
                ],
            ],
        )),
        "pg_catalog.pg_class" => {
            let mut rows = Vec::new();
            for table in catalog
                .tables
                .values()
                .filter(|t| t.state == ObjectState::Live)
            {
                rows.push(vec![
                    Datum::Int32(table.oid as i32),
                    Datum::Text(table.name.clone()),
                    Datum::Int32(table.schema_oid as i32),
                    Datum::Text("r".into()),
                    Datum::Int16(
                        table
                            .columns
                            .iter()
                            .filter(|c| c.state == ColumnState::Live)
                            .count() as i16,
                    ),
                    Datum::Boolean(!table.secondary_indexes.is_empty()),
                    Datum::Float64(table.row_count as f64),
                    Datum::Int32(10),
                    Datum::Text("p".into()),
                ]);
            }
            for index in catalog
                .indexes
                .values()
                .filter(|i| i.state == ObjectState::Live)
            {
                rows.push(vec![
                    Datum::Int32(index.oid as i32),
                    Datum::Text(index.name.clone()),
                    Datum::Int32(2200),
                    Datum::Text("i".into()),
                    Datum::Int16(0),
                    Datum::Boolean(false),
                    Datum::Float64(0.0),
                    Datum::Int32(10),
                    Datum::Text("p".into()),
                ]);
            }
            Some((
                vec![
                    ("oid".into(), i32t),
                    ("relname".into(), text),
                    ("relnamespace".into(), i32t),
                    ("relkind".into(), text),
                    ("relnatts".into(), i16t),
                    ("relhasindex".into(), boolt),
                    ("reltuples".into(), f64t),
                    ("relowner".into(), i32t),
                    ("relpersistence".into(), text),
                ],
                rows,
            ))
        }
        "pg_catalog.pg_attribute" => {
            let mut rows = Vec::new();
            for table in catalog
                .tables
                .values()
                .filter(|t| t.state == ObjectState::Live)
            {
                for (n, column) in table
                    .columns
                    .iter()
                    .filter(|c| c.state == ColumnState::Live)
                    .enumerate()
                {
                    rows.push(vec![
                        Datum::Int32(table.oid as i32),
                        Datum::Text(column.name.clone()),
                        Datum::Int32(column.data_type.oid() as i32),
                        Datum::Int16((n + 1) as i16),
                        Datum::Boolean(!column.nullable),
                        Datum::Boolean(false),
                    ]);
                }
            }
            Some((
                vec![
                    ("attrelid".into(), i32t),
                    ("attname".into(), text),
                    ("atttypid".into(), i32t),
                    ("attnum".into(), i16t),
                    ("attnotnull".into(), boolt),
                    ("attisdropped".into(), boolt),
                ],
                rows,
            ))
        }
        "pg_catalog.pg_type" => {
            let types = [
                ("bool", 16),
                ("bytea", 17),
                ("int8", 20),
                ("int2", 21),
                ("int4", 23),
                ("text", 25),
                ("float8", 701),
                ("varchar", 1043),
                ("date", 1082),
                ("timestamp", 1114),
                ("timestamptz", 1184),
                ("uuid", 2950),
                ("jsonb", 3802),
            ];
            Some((
                vec![
                    ("oid".into(), i32t),
                    ("typname".into(), text),
                    ("typnamespace".into(), i32t),
                    ("typtype".into(), text),
                    ("typrelid".into(), i32t),
                ],
                types
                    .into_iter()
                    .map(|(n, oid)| {
                        vec![
                            Datum::Int32(oid),
                            Datum::Text(n.into()),
                            Datum::Int32(11),
                            Datum::Text("b".into()),
                            Datum::Int32(0),
                        ]
                    })
                    .collect(),
            ))
        }
        "pg_catalog.pg_index" => Some((
            vec![
                ("indexrelid".into(), i32t),
                ("indrelid".into(), i32t),
                ("indisunique".into(), boolt),
                ("indkey".into(), text),
            ],
            catalog
                .indexes
                .values()
                .filter(|i| i.state == ObjectState::Live)
                .map(|i| {
                    vec![
                        Datum::Int32(i.oid as i32),
                        Datum::Int32(i.table_oid as i32),
                        Datum::Boolean(i.unique),
                        Datum::Text(
                            i.columns
                                .iter()
                                .map(|c| c.column_id.to_string())
                                .collect::<Vec<_>>()
                                .join(" "),
                        ),
                    ]
                })
                .collect(),
        )),
        "pg_catalog.pg_constraint" => Some((
            vec![
                ("oid".into(), i32t),
                ("conname".into(), text),
                ("conrelid".into(), i32t),
                ("contype".into(), text),
            ],
            catalog
                .tables
                .values()
                .filter(|t| t.state == ObjectState::Live && t.primary_key.is_some())
                .map(|t| {
                    vec![
                        Datum::Int32((t.oid + 1_000_000) as i32),
                        Datum::Text(format!("{}_pkey", t.name)),
                        Datum::Int32(t.oid as i32),
                        Datum::Text("p".into()),
                    ]
                })
                .collect(),
        )),
        "pg_catalog.pg_database" => Some((
            vec![
                ("oid".into(), i32t),
                ("datname".into(), text),
                ("datallowconn".into(), boolt),
            ],
            vec![vec![
                Datum::Int32(1),
                Datum::Text("app".into()),
                Datum::Boolean(true),
            ]],
        )),
        "pg_catalog.pg_roles" => Some((
            vec![
                ("oid".into(), i32t),
                ("rolname".into(), text),
                ("rolsuper".into(), boolt),
            ],
            vec![vec![
                Datum::Int32(10),
                Datum::Text("app".into()),
                Datum::Boolean(true),
            ]],
        )),
        "information_schema.tables" => Some((
            vec![
                ("table_schema".into(), text),
                ("table_name".into(), text),
                ("table_type".into(), text),
            ],
            catalog
                .tables
                .values()
                .filter(|t| t.state == ObjectState::Live)
                .map(|t| {
                    vec![
                        Datum::Text("public".into()),
                        Datum::Text(t.name.clone()),
                        Datum::Text("BASE TABLE".into()),
                    ]
                })
                .collect(),
        )),
        "information_schema.columns" => {
            let mut rows = Vec::new();
            for table in catalog
                .tables
                .values()
                .filter(|t| t.state == ObjectState::Live)
            {
                for (n, column) in table
                    .columns
                    .iter()
                    .filter(|c| c.state == ColumnState::Live)
                    .enumerate()
                {
                    rows.push(vec![
                        Datum::Text("public".into()),
                        Datum::Text(table.name.clone()),
                        Datum::Text(column.name.clone()),
                        Datum::Int32((n + 1) as i32),
                        Datum::Text(if column.nullable { "YES" } else { "NO" }.into()),
                        Datum::Text(column.data_type.name().into()),
                    ]);
                }
            }
            Some((
                vec![
                    ("table_schema".into(), text),
                    ("table_name".into(), text),
                    ("column_name".into(), text),
                    ("ordinal_position".into(), i32t),
                    ("is_nullable".into(), text),
                    ("data_type".into(), text),
                ],
                rows,
            ))
        }
        _ => None,
    }
}

fn find_table<'a>(c: &'a Catalog, n: &str) -> std::result::Result<&'a TableDescriptor, SqlError> {
    let name = relation_leaf(n);
    c.table_by_name(name)
        .ok_or_else(|| SqlError::new("42P01", format!("relation \"{n}\" does not exist")))
}
fn relation_leaf(n: &str) -> &str {
    n.rsplit_once('.').map(|(_, leaf)| leaf).unwrap_or(n)
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
            qualifier: None,
            value: r
                .get(c.id)
                .cloned()
                .unwrap_or_else(|| c.default.clone().unwrap_or(Datum::Null)),
        })
        .collect()
}
fn validate_fields(
    table: &TableDescriptor,
    fields: &[(u32, Datum)],
) -> std::result::Result<(), SqlError> {
    for column in table
        .columns
        .iter()
        .filter(|c| c.state == ColumnState::Live)
    {
        let value = fields
            .iter()
            .find(|(id, _)| *id == column.id)
            .map(|(_, value)| value)
            .or_else(|| column.default.as_ref())
            .unwrap_or(&Datum::Null);
        if value.is_null() && !column.nullable {
            return Err(SqlError::new(
                "23502",
                format!(
                    "null value in column {} violates not-null constraint",
                    column.name
                ),
            ));
        }
    }
    Ok(())
}
fn encode_row_checked(
    tx: &Transaction,
    row: &chorus_codec::EncodedRowV1,
) -> std::result::Result<Vec<u8>, SqlError> {
    let bytes = row.encode().map_err(codec_sql)?;
    if bytes.len() > tx.limits.max_row_bytes {
        return Err(SqlError::new("54000", "row exceeds configured size limit"));
    }
    Ok(bytes)
}
fn datum_size(value: &Datum) -> usize {
    1 + match value {
        Datum::Null => 0,
        Datum::Boolean(_) => 1,
        Datum::Int16(_) => 2,
        Datum::Int32(_) | Datum::Date(_) => 4,
        Datum::Int64(_) | Datum::Timestamp(_) | Datum::TimestampTz(_) | Datum::Float64(_) => 8,
        Datum::Uuid(_) => 16,
        Datum::Bytes(bytes) => bytes.len(),
        Datum::Text(text) | Datum::Jsonb(text) => text.len(),
    }
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

/// Return physical secondary-index mutations for a row.  The boolean marks a
/// key that must be unique; NULL-containing unique keys deliberately retain a
/// row suffix so PostgreSQL's ordinary "NULLs are distinct" behavior is
/// preserved.
fn index_entries(
    catalog: &Catalog,
    table: &TableDescriptor,
    row: &chorus_codec::EncodedRowV1,
    row_key: &[u8],
) -> std::result::Result<Vec<(Vec<u8>, bool)>, SqlError> {
    let mut out = Vec::new();
    for index_id in &table.secondary_indexes {
        let Some(index) = catalog.indexes.get(index_id) else {
            continue;
        };
        if index.state != ObjectState::Live {
            continue;
        }
        let values = index
            .columns
            .iter()
            .map(|c| row.get(c.column_id).cloned().unwrap_or(Datum::Null))
            .collect::<Vec<_>>();
        let directions = index
            .columns
            .iter()
            .map(|c| c.descending)
            .collect::<Vec<_>>();
        let encoded = encode_composite(&values, &directions).map_err(codec_sql)?;
        let has_null = values.iter().any(Datum::is_null);
        let unique = index.unique && !has_null;
        let key = chorus_codec::PhysicalKey::index(index.oid, &encoded, row_key, unique)
            .map_err(codec_sql)?
            .0;
        out.push((key, unique));
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
fn returning_columns(e: &Expr, t: &TableDescriptor) -> Vec<ResultColumn> {
    if matches!(e, Expr::Star) {
        t.columns
            .iter()
            .filter(|c| c.state == ColumnState::Live)
            .map(|c| ResultColumn {
                name: c.name.clone(),
                data_type: c.data_type,
                table_oid: t.oid,
                column_oid: c.id,
            })
            .collect()
    } else {
        vec![result_column(e, t)]
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

fn cast_value(v: Datum, ty: SqlType) -> std::result::Result<Datum, SqlError> {
    if v.is_null() {
        return Ok(v);
    }
    if let Ok(value) = coerce(v.clone(), ty) {
        return Ok(value);
    }
    match (v, ty) {
        (Datum::Text(text), SqlType::SmallInt) => text
            .trim()
            .parse::<i16>()
            .map(Datum::Int16)
            .map_err(|_| SqlError::new("22P02", "invalid input syntax for smallint")),
        (Datum::Text(text), SqlType::Integer) => text
            .trim()
            .parse::<i32>()
            .map(Datum::Int32)
            .map_err(|_| SqlError::new("22P02", "invalid input syntax for integer")),
        (Datum::Text(text), SqlType::BigInt) => text
            .trim()
            .parse::<i64>()
            .map(Datum::Int64)
            .map_err(|_| SqlError::new("22P02", "invalid input syntax for bigint")),
        (Datum::Text(text), SqlType::Double) => text
            .trim()
            .parse::<f64>()
            .map(Datum::Float64)
            .map_err(|_| SqlError::new("22P02", "invalid input syntax for double precision")),
        (Datum::Text(text), SqlType::Boolean) => text
            .trim()
            .parse::<bool>()
            .map(Datum::Boolean)
            .map_err(|_| SqlError::new("22P02", "invalid input syntax for boolean")),
        (Datum::Text(text), SqlType::Jsonb) => chorus_common::Datum::canonical_json(&text)
            .map(Datum::Jsonb)
            .map_err(|e| SqlError::new("22P02", e.message)),
        (Datum::Text(text), SqlType::Date) => parse_date_literal(&text).map(Datum::Date),
        (Datum::Text(text), SqlType::Timestamp) => {
            parse_timestamp_literal(&text).map(Datum::Timestamp)
        }
        (Datum::Text(text), SqlType::TimestampTz) => {
            parse_timestamp_literal(&text).map(Datum::TimestampTz)
        }
        (Datum::Text(text), SqlType::Uuid) => parse_uuid_text(&text)
            .map(Datum::Uuid)
            .ok_or_else(|| SqlError::new("22P02", "invalid input syntax for uuid")),
        (Datum::Jsonb(json), SqlType::Text) => Ok(Datum::Text(json)),
        (Datum::Bytes(bytes), SqlType::Text) => String::from_utf8(bytes)
            .map(Datum::Text)
            .map_err(|_| SqlError::new("22021", "invalid byte sequence for UTF-8")),
        (value, ty) => Err(SqlError::new(
            "42846",
            format!(
                "cannot cast {} to {}",
                value.sql_type().map(SqlType::name).unwrap_or("unknown"),
                ty.name()
            ),
        )),
    }
}

fn parse_uuid_text(text: &str) -> Option<[u8; 16]> {
    let clean = text.trim().replace('-', "");
    if clean.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn parse_temporal_literal(kind: &str, text: &str) -> std::result::Result<Datum, SqlError> {
    match kind {
        "date" => parse_date_literal(text).map(Datum::Date),
        "timestamp" => parse_timestamp_literal(text).map(Datum::Timestamp),
        "timestamptz" => parse_timestamp_literal(text).map(Datum::TimestampTz),
        _ => Err(SqlError::new("42804", "unsupported temporal literal type")),
    }
}

fn parse_date_literal(text: &str) -> std::result::Result<i32, SqlError> {
    let mut parts = text.trim().split('-');
    let year = parts
        .next()
        .ok_or_else(|| SqlError::new("22007", "invalid date"))?
        .parse::<i64>()
        .map_err(|_| SqlError::new("22007", "invalid date"))?;
    let month = parts
        .next()
        .ok_or_else(|| SqlError::new("22007", "invalid date"))?
        .parse::<i64>()
        .map_err(|_| SqlError::new("22007", "invalid date"))?;
    let day = parts
        .next()
        .ok_or_else(|| SqlError::new("22007", "invalid date"))?
        .parse::<i64>()
        .map_err(|_| SqlError::new("22007", "invalid date"))?;
    if parts.next().is_some() || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(SqlError::new("22007", "invalid date"));
    }
    let y = year - i64::from(month <= 2);
    let era = (if y >= 0 { y } else { y - 399 }).div_euclid(400);
    let yoe = y - era * 400;
    let mp = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    i32::try_from(days).map_err(|_| SqlError::new("22008", "date out of range"))
}

fn parse_timestamp_literal(text: &str) -> std::result::Result<i64, SqlError> {
    let text = text
        .trim()
        .trim_end_matches("+00:00")
        .trim_end_matches("+00");
    let (date, time) = text
        .split_once([' ', 'T'])
        .ok_or_else(|| SqlError::new("22007", "invalid timestamp"))?;
    let days = i64::from(parse_date_literal(date)?);
    let mut fields = time.split(':');
    let hour = fields
        .next()
        .ok_or_else(|| SqlError::new("22007", "invalid timestamp"))?
        .parse::<i64>()
        .map_err(|_| SqlError::new("22007", "invalid timestamp"))?;
    let minute = fields
        .next()
        .ok_or_else(|| SqlError::new("22007", "invalid timestamp"))?
        .parse::<i64>()
        .map_err(|_| SqlError::new("22007", "invalid timestamp"))?;
    let second_text = fields
        .next()
        .ok_or_else(|| SqlError::new("22007", "invalid timestamp"))?;
    if fields.next().is_some() || hour > 23 || minute > 59 {
        return Err(SqlError::new("22007", "invalid timestamp"));
    }
    let (second, micros) = if let Some((whole, fraction)) = second_text.split_once('.') {
        let second = whole
            .parse::<i64>()
            .map_err(|_| SqlError::new("22007", "invalid timestamp"))?;
        let mut fraction = fraction.to_string();
        if fraction.len() > 6 {
            fraction.truncate(6);
        }
        while fraction.len() < 6 {
            fraction.push('0');
        }
        let micros = fraction
            .parse::<i64>()
            .map_err(|_| SqlError::new("22007", "invalid timestamp"))?;
        (second, micros)
    } else {
        (
            second_text
                .parse::<i64>()
                .map_err(|_| SqlError::new("22007", "invalid timestamp"))?,
            0,
        )
    };
    if !(0..=59).contains(&second) {
        return Err(SqlError::new("22007", "invalid timestamp"));
    }
    days.checked_mul(86_400_000_000)
        .and_then(|value| value.checked_add(hour * 3_600_000_000))
        .and_then(|value| value.checked_add(minute * 60_000_000))
        .and_then(|value| value.checked_add(second * 1_000_000))
        .and_then(|value| value.checked_add(micros))
        .ok_or_else(|| SqlError::new("22008", "timestamp out of range"))
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
        JsonGet | JsonText => {
            let Datum::Jsonb(json) = a else {
                return Err(SqlError::new("42883", "json operator requires jsonb"));
            };
            let value: serde_json::Value = serde_json::from_str(json)
                .map_err(|_| SqlError::new("22P02", "invalid jsonb value"))?;
            let selected = match b {
                Datum::Text(key) => value.get(key),
                Datum::Int16(index) => value.get((*index).max(0) as usize),
                Datum::Int32(index) => value.get((*index).max(0) as usize),
                Datum::Int64(index) => value.get((*index).max(0) as usize),
                _ => None,
            };
            let Some(selected) = selected else {
                return Ok(Datum::Null);
            };
            if matches!(op, JsonText) {
                Ok(Datum::Text(match selected {
                    serde_json::Value::String(s) => s.clone(),
                    _ => selected.to_string(),
                }))
            } else {
                Ok(Datum::Jsonb(
                    chorus_common::Datum::canonical_json(&selected.to_string())
                        .map_err(|e| SqlError::new("22P02", e.message))?,
                ))
            }
        }
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
        "application_name" => {
            if v.eq_ignore_ascii_case("default") {
                s.application_name.clear();
            } else {
                s.application_name = v.into();
            }
        }
        "search_path" if v == "public" || v == "public, pg_catalog" => s.search_path = v.into(),
        "client_encoding" if v.eq_ignore_ascii_case("utf8") || v.eq_ignore_ascii_case("utf-8") => {
            s.client_encoding = "UTF8".into()
        }
        "timezone" if v.eq_ignore_ascii_case("utc") => s.timezone = "UTC".into(),
        "datestyle" if v.to_ascii_uppercase().starts_with("ISO") => s.datestyle = v.into(),
        "transaction_isolation" => s.transaction_isolation = "serializable".into(),
        "transaction" => {
            s.transaction_isolation = "serializable".into();
            if v.to_ascii_lowercase().contains("read only") {
                s.transaction_read_only = true;
            }
        }
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
            let name = relation_leaf(&name).to_string();
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
        Statement::DropTable { name, if_exists } => {
            let name = relation_leaf(&name);
            match c.table_by_name(name) {
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
            }
        }
        Statement::AlterTable { table, op } => {
            let table = relation_leaf(&table);
            let t = c
                .table_by_name(table)
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
            let name = relation_leaf(&name).to_string();
            let table = relation_leaf(&table).to_string();
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
        Statement::DropIndex { name, if_exists } => {
            let name = relation_leaf(&name);
            match c.index_by_name(name) {
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
            }
        }
        _ => Err(SqlError::unsupported("not a schema statement")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chorus_storage::MemoryStateStore;
    use chorus_txn::LocalCommitter;
    use std::collections::BTreeMap;
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

    #[test]
    fn temporal_literals_and_current_date_are_typed() {
        let parsed = Parser::batch(
            "SELECT DATE '2024-01-02', TIMESTAMP '2024-01-02 03:04:05.123', current_date",
        )
        .unwrap();
        let Statement::Select(select) = &parsed[0] else {
            panic!("expected select");
        };
        assert!(matches!(
            select.projection[0],
            Expr::Literal(Datum::Date(_))
        ));
        assert!(matches!(
            select.projection[1],
            Expr::Literal(Datum::Timestamp(_))
        ));
        assert!(matches!(select.projection[2], Expr::Func(ref name, _) if name == "current_date"));
    }

    #[test]
    fn secondary_unique_index_and_virtual_catalog() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
        let origin = OriginId::new(7);
        let committer: Arc<dyn Committer> =
            Arc::new(LocalCommitter::new(store.clone(), origin).unwrap());
        let engine = SqlEngine::new(store.clone(), committer, Limits::default());
        let mut session = engine.session();
        session
            .execute(
                "CREATE TABLE accounts (id integer primary key, email text);",
                &[],
            )
            .unwrap();
        session
            .execute(
                "CREATE UNIQUE INDEX accounts_email_idx ON accounts (email);",
                &[],
            )
            .unwrap();
        session
            .execute("INSERT INTO accounts VALUES (1, 'a@example.com');", &[])
            .unwrap();
        let duplicate = session.execute("INSERT INTO accounts VALUES (2, 'a@example.com');", &[]);
        assert_eq!(duplicate.unwrap_err().code, "23505");
        session
            .execute("INSERT INTO accounts VALUES (2, NULL);", &[])
            .unwrap();
        session
            .execute("DELETE FROM accounts WHERE id = 1;", &[])
            .unwrap();
        let catalog = session
            .execute(
                "SELECT relname FROM pg_catalog.pg_class WHERE relname = 'accounts';",
                &[],
            )
            .unwrap();
        assert_eq!(catalog.rows, vec![vec![Datum::Text("accounts".into())]]);
        let columns = session
            .execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name = 'accounts' ORDER BY ordinal_position;",
                &[],
            )
            .unwrap();
        assert_eq!(columns.rows.len(), 2);
    }

    #[test]
    fn grouped_aggregates() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
        let origin = OriginId::new(8);
        let committer: Arc<dyn Committer> =
            Arc::new(LocalCommitter::new(store.clone(), origin).unwrap());
        let engine = SqlEngine::new(store, committer, Limits::default());
        let mut session = engine.session();
        session
            .execute(
                "CREATE TABLE events (id integer primary key, kind text, value integer);",
                &[],
            )
            .unwrap();
        session
            .execute(
                "INSERT INTO events VALUES (1,'a',2),(2,'a',4),(3,'b',8);",
                &[],
            )
            .unwrap();
        let grouped = session
            .execute(
                "SELECT kind, count(*), sum(value), avg(value) FROM events GROUP BY kind ORDER BY kind;",
                &[],
            )
            .unwrap();
        assert_eq!(grouped.rows.len(), 2);
        assert_eq!(grouped.rows[0][1], Datum::Int64(2));
        assert_eq!(grouped.rows[0][2], Datum::Int64(6));
    }

    #[test]
    fn inner_and_left_join() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
        let origin = OriginId::new(9);
        let committer: Arc<dyn Committer> =
            Arc::new(LocalCommitter::new(store.clone(), origin).unwrap());
        let engine = SqlEngine::new(store, committer, Limits::default());
        let mut session = engine.session();
        session
            .execute(
                "CREATE TABLE parents (id integer primary key, name text);",
                &[],
            )
            .unwrap();
        session
            .execute(
                "CREATE TABLE children (id integer primary key, parent_id integer);",
                &[],
            )
            .unwrap();
        session
            .execute("INSERT INTO parents VALUES (1,'one'),(2,'two');", &[])
            .unwrap();
        session
            .execute("INSERT INTO children VALUES (10,1);", &[])
            .unwrap();
        let result = session
            .execute(
                "SELECT p.id, c.id FROM parents AS p LEFT JOIN children AS c ON p.id = c.parent_id ORDER BY p.id;",
                &[],
            )
            .unwrap();
        assert_eq!(result.rows.len(), 2);
        assert_eq!(result.rows[0][1], Datum::Int32(10));
        assert!(result.rows[1][1].is_null());
    }

    #[test]
    fn on_conflict_update_uses_excluded_row() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
        let origin = OriginId::new(10);
        let committer: Arc<dyn Committer> =
            Arc::new(LocalCommitter::new(store.clone(), origin).unwrap());
        let engine = SqlEngine::new(store, committer, Limits::default());
        let mut session = engine.session();
        session
            .execute(
                "CREATE TABLE counters (id integer primary key, value integer);",
                &[],
            )
            .unwrap();
        session
            .execute("INSERT INTO counters VALUES (1, 2);", &[])
            .unwrap();
        session
            .execute(
                "INSERT INTO counters VALUES (1, 7) ON CONFLICT (id) DO UPDATE SET value = excluded.value;",
                &[],
            )
            .unwrap();
        let result = session
            .execute("SELECT value FROM counters WHERE id = 1;", &[])
            .unwrap();
        assert_eq!(result.rows, vec![vec![Datum::Int32(7)]]);
    }

    #[test]
    fn casts_json_and_coalesce() {
        let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::new());
        let origin = OriginId::new(11);
        let committer: Arc<dyn Committer> =
            Arc::new(LocalCommitter::new(store.clone(), origin).unwrap());
        let engine = SqlEngine::new(store, committer, Limits::default());
        let mut session = engine.session();
        let result = session
            .execute(
                "SELECT ('7'::integer) + 1, '{\"answer\":42}'::jsonb ->> 'answer', coalesce(NULL, 'ok');",
                &[],
            )
            .unwrap();
        assert_eq!(result.rows[0][0], Datum::Int64(8));
        assert_eq!(result.rows[0][1], Datum::Text("42".into()));
        assert_eq!(result.rows[0][2], Datum::Text("ok".into()));
    }

    #[test]
    fn engine_shares_sequencer_across_sessions() {
        let mut data = chorus_storage::StateData::default();
        data.catalog.next_object_id = 10;
        data.catalog.tables = BTreeMap::from([(
            1,
            TableDescriptor {
                oid: 1,
                schema_oid: 2200,
                name: "items".into(),
                schema_version: 1,
                columns: vec![ColumnDescriptor {
                    id: 2,
                    name: "id".into(),
                    data_type: SqlType::Integer,
                    nullable: false,
                    default: None,
                    state: ColumnState::Live,
                }],
                primary_key: Some(2),
                secondary_indexes: Vec::new(),
                row_count: 0,
                state: ObjectState::Live,
            },
        )]);
        let store: Arc<dyn StateStore> = Arc::new(MemoryStateStore::from_data(data));
        let origin = OriginId::new(12);
        let committer: Arc<dyn Committer> =
            Arc::new(LocalCommitter::new(store.clone(), origin).unwrap());
        let engine = SqlEngine::new(store.clone(), committer, Limits::default());
        let mut first = engine.session();
        let mut second = engine.session();

        first.execute("INSERT INTO items VALUES (1);", &[]).unwrap();
        assert_eq!(store.snapshot().unwrap().db_epoch(), 1);
        assert_eq!(engine.sequencer.next_sequence_hint(), 2);

        second
            .execute("INSERT INTO items VALUES (2);", &[])
            .unwrap();
        assert_eq!(store.snapshot().unwrap().db_epoch(), 2);
        assert_eq!(engine.sequencer.next_sequence_hint(), 3);
    }
}
