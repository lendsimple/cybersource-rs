//! The intermediate representation: named models and operations, built from
//! the spec with every inline schema hoisted, named and de-duplicated.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde_json::Value;

use super::config::Config;
use super::{docs, naming};

/// A Rust field or element type.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ty {
    String,
    I32,
    I64,
    F64,
    Bool,
    /// Arbitrary JSON.
    Value,
    Vec(Box<Ty>),
    /// A JSON object used as a string-keyed map.
    Map(Box<Ty>),
    /// A generated model, by name.
    Model(String),
}

impl fmt::Display for Ty {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ty::String => f.write_str("String"),
            Ty::I32 => f.write_str("i32"),
            Ty::I64 => f.write_str("i64"),
            Ty::F64 => f.write_str("f64"),
            Ty::Bool => f.write_str("bool"),
            Ty::Value => f.write_str("Value"),
            Ty::Vec(t) => write!(f, "Vec<{t}>"),
            Ty::Map(t) => write!(f, "Map<{t}>"),
            Ty::Model(n) => f.write_str(n),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field {
    pub json_name: String,
    pub rust_name: String,
    pub ty: Ty,
    pub doc: Option<String>,
    pub sensitive: bool,
    pub constraints: Constraints,
}

/// What the spec allows for a field's value. Length, pattern and range
/// apply to the value itself or, for an array, to each item.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Constraints {
    pub required: bool,
    pub min_length: Option<u64>,
    pub max_length: Option<u64>,
    /// The spec's pattern, verbatim.
    pub pattern: Option<String>,
    pub minimum: Option<f64>,
    pub maximum: Option<f64>,
    pub min_items: Option<u64>,
    pub max_items: Option<u64>,
}

impl Constraints {
    fn read(prop: &Value, required: bool) -> Self {
        let uint = |v: &Value, key| v.get(key).and_then(Value::as_u64);
        let num = |v: &Value, key| v.get(key).and_then(Value::as_f64);
        let is_array = prop.get("type").and_then(Value::as_str) == Some("array");
        let value = if is_array {
            prop.get("items").unwrap_or(&Value::Null)
        } else {
            prop
        };
        Constraints {
            required,
            min_length: uint(value, "minLength"),
            max_length: uint(value, "maxLength"),
            pattern: value
                .get("pattern")
                .and_then(Value::as_str)
                .map(str::to_owned),
            minimum: num(value, "minimum"),
            maximum: num(value, "maximum"),
            min_items: is_array.then(|| uint(prop, "minItems")).flatten(),
            max_items: is_array.then(|| uint(prop, "maxItems")).flatten(),
        }
    }

    /// The loosest constraints satisfying both: a model shared by several
    /// operations must not reject what any of them allows.
    fn loosest(&self, other: &Self) -> Self {
        fn both<T: Copy>(a: Option<T>, b: Option<T>, pick: fn(T, T) -> T) -> Option<T> {
            Some(pick(a?, b?))
        }
        Constraints {
            required: self.required && other.required,
            min_length: both(self.min_length, other.min_length, u64::min),
            max_length: both(self.max_length, other.max_length, u64::max),
            pattern: self
                .pattern
                .clone()
                .filter(|_| self.pattern == other.pattern),
            minimum: both(self.minimum, other.minimum, f64::min),
            maximum: both(self.maximum, other.maximum, f64::max),
            min_items: both(self.min_items, other.min_items, u64::min),
            max_items: both(self.max_items, other.max_items, u64::max),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Model {
    pub name: String,
    /// The spec title, when it differs from `name`.
    pub alias: Option<String>,
    pub doc: Option<String>,
    pub fields: Vec<Field>,
    /// Feature groups whose operations reach this model.
    pub groups: BTreeSet<String>,
    /// Where it was first seen, for error messages.
    pub pointer: String,
}

impl Model {
    /// Structural identity: field names and types, ignoring docs.
    fn fingerprint(&self) -> String {
        self.fields
            .iter()
            .map(|f| format!("{}:{}", f.json_name, f.ty))
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParamIn {
    Path,
    Query,
    Header,
}

#[derive(Debug, Clone)]
pub struct Param {
    pub json_name: String,
    pub rust_name: String,
    pub location: ParamIn,
    pub ty: Ty,
    pub required: bool,
    pub doc: Option<String>,
}

/// What a successful response decodes to.
#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    /// No body.
    Unit,
    /// Non-JSON content (CSV, XML, PDF...), returned raw.
    Bytes,
    /// A plain string body (e.g. a JWT).
    Text,
    /// A JSON body.
    Json(Ty),
    /// Different bodies per status: (status, type or no body).
    ByStatus(Vec<(u16, Option<Ty>)>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mle {
    Never,
    Optional,
    Mandatory,
}

#[derive(Debug, Clone)]
pub struct Operation {
    /// camelCase operation id.
    pub id: String,
    /// snake_case method name.
    pub fn_name: String,
    /// PascalCase struct name.
    pub struct_name: String,
    pub method: String,
    pub path: String,
    pub group: String,
    pub params: Vec<Param>,
    pub body: Option<Ty>,
    pub output: Output,
    /// `Accept` header when not JSON.
    pub accept: Option<String>,
    pub mle_request: Mle,
    pub mle_response: Mle,
    pub retry_safe: bool,
    pub no_auth: bool,
    /// The body has `clientReferenceInformation.partner.developerId`.
    pub developer_id: bool,
    /// How to page through the response, for list operations.
    pub pagination: Option<Pagination>,
    pub doc: Option<String>,
    /// Request body examples from `x-example`.
    pub request_examples: Vec<Example>,
    /// JSON success response examples, keyed by status.
    pub response_examples: Vec<(u16, Example)>,
}

/// How a list operation's response describes a page (Rust field names).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pagination {
    pub total: String,
    pub count: PageCount,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageCount {
    /// An integer field holding the page's item count.
    Field(String),
    /// An array field holding the page's items.
    Items(String),
}

/// A spec example, checked against its own schema.
#[derive(Debug, Clone)]
pub struct Example {
    pub name: String,
    pub value: Value,
    /// Paths (`$.a.b[0]`) where the example disagrees with its schema
    /// (undeclared fields, convertible type mismatches): spec errata the
    /// round-trip test ignores.
    pub ignore: Vec<String>,
    /// Set when the example cannot match its schema at all.
    pub skip: Option<String>,
}

impl Example {
    fn new(name: String, value: Value, schema: &Value) -> Self {
        let mut example = Example {
            name,
            value: Value::Null,
            ignore: Vec::new(),
            skip: None,
        };
        errata(schema, &value, "$", &mut example);
        example.value = value;
        example
    }
}

/// Records where `value` disagrees with `schema` (see [`Example`]).
fn errata(schema: &Value, value: &Value, path: &str, ex: &mut Example) {
    if value.is_null() || ex.skip.is_some() {
        return;
    }
    let skip = |ex: &mut Example, what: &str| {
        ex.skip = Some(format!(
            "{path}: example has {value}, schema expects {what}"
        ));
    };
    let ty = schema.get("type").and_then(Value::as_str);
    let props = schema
        .get("properties")
        .and_then(Value::as_object)
        .filter(|p| !p.is_empty());
    let additional = schema.get("additionalProperties");
    match (ty, props) {
        (Some("object") | None, Some(props)) => {
            let Some(obj) = value.as_object() else {
                return skip(ex, "an object");
            };
            for (key, v) in obj {
                let child = format!("{path}.{key}");
                match props.get(key) {
                    Some(prop) => errata(prop, v, &child, ex),
                    None => ex.ignore.push(child),
                }
            }
        }
        (Some("object"), None) => match additional {
            Some(ap @ Value::Object(m)) if !m.is_empty() => {
                let Some(obj) = value.as_object() else {
                    return skip(ex, "a map");
                };
                for (key, v) in obj {
                    errata(ap, v, &format!("{path}.{key}"), ex);
                }
            }
            _ => {}
        },
        (Some("array"), _) => {
            let Some(items) = value.as_array() else {
                return skip(ex, "an array");
            };
            let item_schema = schema.get("items").unwrap_or(&Value::Null);
            for (i, v) in items.iter().enumerate() {
                errata(item_schema, v, &format!("{path}[{i}]"), ex);
            }
        }
        (Some("string"), _) => {
            if value.is_object() || value.is_array() {
                skip(ex, "a string");
            } else if !value.is_string() {
                ex.ignore.push(path.to_owned());
            }
        }
        (Some("integer" | "number"), _) => match value {
            Value::Number(n) if ty == Some("number") || n.is_i64() || n.is_u64() => {}
            Value::String(s) if s.trim().parse::<f64>().is_ok() => ex.ignore.push(path.to_owned()),
            _ => skip(ex, "a number"),
        },
        (Some("boolean"), _) => match value {
            Value::Bool(_) => {}
            Value::String(s)
                if matches!(
                    s.trim().to_ascii_lowercase().as_str(),
                    "true" | "false" | "1" | "0" | "y" | "n" | "yes" | "no"
                ) =>
            {
                ex.ignore.push(path.to_owned())
            }
            _ => skip(ex, "a boolean"),
        },
        _ => {}
    }
}

#[derive(Debug, Default)]
pub struct Ir {
    pub models: BTreeMap<String, Model>,
    pub operations: Vec<Operation>,
}

impl Ir {
    /// Models reachable from a request body: the ones that get validated.
    pub fn request_models(&self) -> BTreeSet<String> {
        fn visit(ir: &Ir, ty: &Ty, seen: &mut BTreeSet<String>) {
            match ty {
                Ty::Vec(t) | Ty::Map(t) => visit(ir, t, seen),
                Ty::Model(name) if seen.insert(name.clone()) => {
                    for field in &ir.models[name].fields {
                        visit(ir, &field.ty, seen);
                    }
                }
                _ => {}
            }
        }
        let mut seen = BTreeSet::new();
        for op in &self.operations {
            if let Some(body) = &op.body {
                visit(self, body, &mut seen);
            }
        }
        seen
    }
}

/// Builds the IR, returning every problem found rather than the first.
pub fn build(spec: &Value, config: &Config) -> Result<Ir, Vec<String>> {
    let mut b = Builder {
        config,
        ir: Ir::default(),
        errors: Vec::new(),
        op_ids: BTreeMap::new(),
    };
    let paths = spec
        .get("paths")
        .and_then(Value::as_object)
        .ok_or_else(|| vec!["spec has no paths".to_string()])?;
    for (path, item) in paths {
        let Some(item) = item.as_object() else {
            continue;
        };
        for (method, op) in item {
            if matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete") {
                b.operation(path, method, op);
            }
        }
    }
    let unused: Vec<_> = config
        .skip_operations
        .keys()
        .chain(config.operation_ids.keys())
        .filter(|k| !b.op_ids.values().any(|v| v == *k) && !b.seen_key(spec, k))
        .collect();
    for key in unused {
        b.errors.push(format!(
            "codegen.toml refers to `{key}`, which is not in the spec"
        ));
    }
    b.pagination();
    if b.errors.is_empty() {
        b.ir.operations
            .sort_by(|a, b| (&a.group, &a.id).cmp(&(&b.group, &b.id)));
        Ok(b.ir)
    } else {
        Err(b.errors)
    }
}

struct Builder<'c> {
    config: &'c Config,
    ir: Ir,
    errors: Vec<String>,
    /// operation id -> "METHOD /path", to detect duplicates.
    op_ids: BTreeMap<String, String>,
}

/// JSON pointer escaping for one path segment.
fn pointer_segment(s: &str) -> String {
    s.replace('~', "~0").replace('/', "~1")
}

fn is_json_media(m: &str) -> bool {
    m.contains("json") || m.starts_with("*/*")
}

impl Builder<'_> {
    /// Resolves `[pagination]` entries against operations and response models.
    fn pagination(&mut self) {
        for (id, spec) in &self.config.pagination {
            let Some(op) = self.ir.operations.iter_mut().find(|o| &o.id == id) else {
                self.errors
                    .push(format!("[pagination] names unknown operation `{id}`"));
                continue;
            };
            let paging_params = ["offset", "limit"].iter().all(|name| {
                op.params
                    .iter()
                    .any(|p| p.json_name == *name && p.ty == Ty::I64)
            });
            let model = match &op.output {
                Output::Json(Ty::Model(m)) => self.ir.models.get(m),
                _ => None,
            };
            let (Some(model), true) = (model, paging_params) else {
                self.errors.push(format!(
                    "[pagination] `{id}` needs i64 offset/limit params and a JSON model response"
                ));
                continue;
            };
            let field = |json: &str| model.fields.iter().find(|f| f.json_name == json);
            let is_int = |f: &Field| matches!(f.ty, Ty::I32 | Ty::I64);
            let total = field(&spec.total).filter(|f| is_int(f));
            let count = match (&spec.count, &spec.items) {
                (Some(c), None) => field(c)
                    .filter(|f| is_int(f))
                    .map(|f| PageCount::Field(f.rust_name.clone())),
                (None, Some(i)) => field(i)
                    .filter(|f| matches!(f.ty, Ty::Vec(_)))
                    .map(|f| PageCount::Items(f.rust_name.clone())),
                _ => None,
            };
            match (total, count) {
                (Some(total), Some(count)) => {
                    op.pagination = Some(Pagination {
                        total: total.rust_name.clone(),
                        count,
                    });
                }
                _ => self.errors.push(format!(
                    "[pagination] `{id}`: `total` must name an integer field and exactly one of \
                     `count` (integer) or `items` (array) must name a field of `{}`",
                    model.name
                )),
            }
        }
    }

    fn seen_key(&self, spec: &Value, key: &str) -> bool {
        let Some((method, path)) = key.split_once(' ') else {
            return false;
        };
        spec.pointer(&format!(
            "/paths/{}/{}",
            pointer_segment(path),
            method.to_ascii_lowercase()
        ))
        .is_some()
    }

    fn operation(&mut self, path: &str, method: &str, op: &Value) {
        let key = format!("{} {path}", method.to_ascii_uppercase());
        if self.config.skip_operations.contains_key(&key) {
            return;
        }
        let pointer = format!("/paths/{}/{method}", pointer_segment(path));

        let id = match self.config.operation_ids.get(&key).cloned().or_else(|| {
            op.get("operationId")
                .and_then(Value::as_str)
                .map(str::to_owned)
        }) {
            Some(id) => id,
            None => {
                self.errors.push(format!(
                    "{key} has no operationId; add one under [operation_ids] in codegen.toml"
                ));
                return;
            }
        };
        if let Some(other) = self.op_ids.insert(id.clone(), key.clone()) {
            self.errors.push(format!(
                "operationId `{id}` is used by both {other} and {key}; \
                 give them distinct ids under [operation_ids] in codegen.toml"
            ));
            return;
        }

        let tag = op
            .pointer("/tags/0")
            .and_then(Value::as_str)
            .unwrap_or("<untagged>");
        let Some(group) = self.config.group_of(tag).map(str::to_owned) else {
            self.errors.push(format!(
                "{key}: tag `{tag}` is not mapped to a feature group in codegen.toml [groups]"
            ));
            return;
        };

        let mut params = Vec::new();
        let mut body = None;
        let mut names = BTreeSet::new();
        for (i, p) in op
            .get("parameters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
        {
            let name = p.get("name").and_then(Value::as_str).unwrap_or_default();
            let location = match p.get("in").and_then(Value::as_str) {
                Some("path") => ParamIn::Path,
                Some("query") => ParamIn::Query,
                Some("header") => {
                    if self
                        .config
                        .pipeline_headers
                        .contains(&name.to_ascii_lowercase())
                    {
                        continue;
                    }
                    ParamIn::Header
                }
                Some("body") => {
                    let ctx = naming::type_name(name);
                    let schema_ptr = format!("{pointer}/parameters/{i}/schema");
                    body = Some(self.schema_ty(
                        p.get("schema").unwrap_or(&Value::Null),
                        &ctx,
                        &schema_ptr,
                        &group,
                    ));
                    continue;
                }
                other => {
                    self.errors.push(format!(
                        "{key}: parameter `{name}` in {other:?} is not supported; \
                         skip the operation in codegen.toml"
                    ));
                    continue;
                }
            };
            let rust_name = naming::field_name(name);
            if !names.insert(rust_name.clone()) || rust_name == "body" {
                self.errors
                    .push(format!("{key}: parameter name `{rust_name}` is not unique"));
                continue;
            }
            params.push(Param {
                json_name: name.to_owned(),
                rust_name,
                location,
                ty: scalar_ty(p),
                required: location == ParamIn::Path
                    || p.get("required").and_then(Value::as_bool).unwrap_or(false),
                doc: describe(p),
            });
        }

        let (output, accept) = self.output(op, &pointer, &id, &group);
        let body_schema = op
            .get("parameters")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .find(|p| p.get("in").and_then(Value::as_str) == Some("body"))
            .and_then(|p| p.get("schema"));
        let meta = op.get("x-devcenter-metaData");
        let mle = |k: &str| match meta.and_then(|m| m.get(k)).and_then(Value::as_str) {
            Some("mandatory") => Mle::Mandatory,
            Some("optional") => Mle::Optional,
            _ => Mle::Never,
        };

        self.ir.operations.push(Operation {
            fn_name: naming::field_name(&id),
            struct_name: naming::type_name(&id),
            id,
            method: method.to_ascii_uppercase(),
            path: path.to_owned(),
            group,
            params,
            body,
            output,
            accept,
            mle_request: mle("mleForRequest"),
            mle_response: mle("mleForResponse"),
            retry_safe: !self.config.money_movement.contains(&key),
            no_auth: meta
                .and_then(|m| m.get("noAuth"))
                .and_then(Value::as_bool)
                .unwrap_or(false),
            developer_id: body_schema.is_some_and(|b| {
                b.pointer("/properties/clientReferenceInformation/properties/partner/properties/developerId")
                    .is_some()
            }),
            pagination: None,
            doc: op
                .get("summary")
                .and_then(Value::as_str)
                .and_then(docs::summary)
                .or_else(|| describe(op)),
            request_examples: op
                .get("x-example")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .filter_map(|(name, ex)| {
                    Some(Example::new(
                        name.clone(),
                        ex.get("value")?.clone(),
                        body_schema?,
                    ))
                })
                .collect(),
            response_examples: op
                .get("responses")
                .and_then(Value::as_object)
                .into_iter()
                .flatten()
                .filter_map(|(code, r)| {
                    let status = code
                        .parse::<u16>()
                        .ok()
                        .filter(|s| (200..300).contains(s))?;
                    let value = r.pointer("/examples/application~1json")?.clone();
                    Some((status, Example::new(code.clone(), value, r.get("schema")?)))
                })
                .collect(),
        });
    }

    fn output(
        &mut self,
        op: &Value,
        pointer: &str,
        id: &str,
        group: &str,
    ) -> (Output, Option<String>) {
        let produces: Vec<&str> = op
            .get("produces")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let json = produces.is_empty() || produces.iter().any(|m| is_json_media(m));
        // JWT/JOSE bodies are compact strings: decode as text, not bytes.
        let token = !json
            && produces
                .iter()
                .all(|m| m.contains("jwt") || m.contains("jose"));
        let raw_accept = (!json).then(|| produces.join(", "));

        let mut by_status = Vec::new();
        if let Some(responses) = op.get("responses").and_then(Value::as_object) {
            for (code, resp) in responses {
                let Ok(status) = code.parse::<u16>() else {
                    continue;
                };
                if !(200..300).contains(&status) {
                    continue;
                }
                let ty = match resp.get("schema") {
                    None => None,
                    Some(_) if !json => None,
                    Some(schema)
                        if schema.get("type").and_then(Value::as_str) == Some("string") =>
                    {
                        Some(Ty::String)
                    }
                    Some(schema) => Some(self.schema_ty(
                        schema,
                        &naming::type_name(&format!("{id}{code}Response")),
                        &format!("{pointer}/responses/{code}/schema"),
                        group,
                    )),
                };
                by_status.push((status, ty));
            }
        }
        by_status.sort_by_key(|(s, _)| *s);

        if token {
            return (Output::Text, raw_accept);
        }
        if !json {
            return (Output::Bytes, raw_accept);
        }
        let distinct: BTreeSet<_> = by_status.iter().map(|(_, t)| t.clone()).collect();
        let output = match distinct.len() {
            0 => Output::Unit,
            1 => match distinct.into_iter().next().unwrap() {
                None => Output::Unit,
                Some(Ty::String) => Output::Text,
                Some(ty) => Output::Json(ty),
            },
            _ => Output::ByStatus(by_status),
        };
        (output, None)
    }

    /// Maps a schema to a type, hoisting and registering object schemas.
    fn schema_ty(&mut self, schema: &Value, ctx: &str, pointer: &str, group: &str) -> Ty {
        let ty = schema.get("type").and_then(Value::as_str);
        let props = schema.get("properties").and_then(Value::as_object);
        match ty {
            Some("array") => Ty::Vec(Box::new(self.schema_ty(
                schema.get("items").unwrap_or(&Value::Null),
                ctx,
                &format!("{pointer}/items"),
                group,
            ))),
            Some("object") | None if props.is_some_and(|p| !p.is_empty()) => {
                self.model(schema, props.unwrap(), ctx, pointer, group)
            }
            Some("object") => match schema.get("additionalProperties") {
                Some(ap @ Value::Object(m)) if !m.is_empty() => Ty::Map(Box::new(self.schema_ty(
                    ap,
                    &format!("{ctx}Value"),
                    &format!("{pointer}/additionalProperties"),
                    group,
                ))),
                _ => Ty::Value,
            },
            _ => scalar_ty(schema),
        }
    }

    fn model(
        &mut self,
        schema: &Value,
        props: &serde_json::Map<String, Value>,
        ctx: &str,
        pointer: &str,
        group: &str,
    ) -> Ty {
        let title = schema.get("title").and_then(Value::as_str);
        let base = title.map_or_else(|| ctx.to_owned(), naming::type_name);
        let name = self
            .config
            .model_renames
            .get(&format!("{base}@{pointer}"))
            .cloned()
            .unwrap_or(base);

        let required: BTreeSet<&str> = schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .collect();
        let mut fields: Vec<Field> = Vec::new();
        for (json_name, prop) in props {
            let child_ctx = format!("{name}{}", naming::type_name(json_name));
            let ty = self.schema_ty(
                prop,
                &child_ctx,
                &format!("{pointer}/properties/{}", pointer_segment(json_name)),
                group,
            );
            fields.push(Field {
                rust_name: naming::field_name(json_name),
                sensitive: self.config.is_sensitive(&name, json_name),
                json_name: json_name.clone(),
                ty,
                doc: describe(prop),
                constraints: Constraints::read(prop, required.contains(json_name.as_str())),
            });
        }
        dedupe_field_names(&mut fields);

        let model = Model {
            alias: title.filter(|t| *t != name).map(str::to_owned),
            doc: describe(schema),
            fields,
            groups: BTreeSet::from([group.to_owned()]),
            pointer: pointer.to_owned(),
            name: name.clone(),
        };
        match self.ir.models.get_mut(&name) {
            Some(existing) if existing.fingerprint() == model.fingerprint() => {
                existing.groups.insert(group.to_owned());
                for (old, new) in existing.fields.iter_mut().zip(&model.fields) {
                    old.constraints = old.constraints.loosest(&new.constraints);
                }
            }
            Some(existing) => {
                let msg = format!(
                    "two different schemas are both named `{name}`:\n    first at {}\n    again at {pointer}\n  \
                     add `\"{name}@{pointer}\" = \"<NewName>\"` under [model_renames] in codegen.toml",
                    existing.pointer
                );
                if !self.errors.contains(&msg) {
                    self.errors.push(msg);
                }
            }
            None => {
                if !naming::is_ident(&name) {
                    self.errors.push(format!(
                        "`{name}` (at {pointer}) is not a valid Rust type name"
                    ));
                }
                self.ir.models.insert(name.clone(), model);
            }
        }
        Ty::Model(name)
    }
}

fn describe(v: &Value) -> Option<String> {
    v.get("description")
        .and_then(Value::as_str)
        .and_then(docs::summary)
}

fn scalar_ty(schema: &Value) -> Ty {
    match (
        schema.get("type").and_then(Value::as_str),
        schema.get("format").and_then(Value::as_str),
    ) {
        (Some("string"), _) => Ty::String,
        (Some("integer"), Some("int32")) => Ty::I32,
        (Some("integer"), _) => Ty::I64,
        (Some("number"), _) => Ty::F64,
        (Some("boolean"), _) => Ty::Bool,
        _ => Ty::Value,
    }
}

/// Resolves fields whose Rust names collide (e.g. `_links` and `links`):
/// the property without a leading underscore keeps the plain name.
fn dedupe_field_names(fields: &mut [Field]) {
    let mut taken: BTreeSet<String> = fields
        .iter()
        .filter(|f| !f.json_name.starts_with('_'))
        .map(|f| f.rust_name.clone())
        .collect();
    for f in fields.iter_mut().filter(|f| f.json_name.starts_with('_')) {
        if !taken.insert(f.rust_name.clone()) {
            let mut n = 2;
            while !taken.insert(format!("{}_{n}", f.rust_name)) {
                n += 1;
            }
            f.rust_name = format!("{}_{n}", f.rust_name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn config() -> Config {
        Config::parse(
            r#"
            money_movement = ["POST /pts/v2/payments"]
            pipeline_headers = ["content-type", "v-c-merchant-id"]
            [groups]
            payments = ["payments"]
            tms = ["Customer"]
            [sensitive]
            always = ["securityCode"]
            number_in_types_containing = ["Card"]
            "#,
        )
        .unwrap()
    }

    fn payment_op() -> Value {
        json!({
            "tags": ["payments"],
            "operationId": "createPayment",
            "summary": "Process a Payment",
            "parameters": [
                {"in": "header", "name": "Content-Type", "type": "string", "required": true},
                {"in": "body", "name": "createPaymentRequest", "schema": {
                    "type": "object",
                    "properties": {
                        "clientReferenceInformation": {
                            "type": "object", "title": "Ptsv2paymentsClientReferenceInformation",
                            "properties": {"code": {"type": "string", "description": "Order ref."}}
                        },
                        "paymentInformation": {
                            "type": "object",
                            "properties": {"card": {
                                "type": "object",
                                "properties": {
                                    "number": {"type": "string"},
                                    "securityCode": {"type": "string"}
                                }
                            }}
                        }
                    }
                }}
            ],
            "responses": {
                "201": {"schema": {"type": "object", "title": "ptsV2PaymentsPost201Response",
                    "properties": {
                        "_links": {"type": "object", "properties": {"self": {"type": "object", "properties": {"href": {"type": "string"}}}}},
                        "id": {"type": "string"},
                        "type": {"type": "string"}
                    }}},
                "400": {"schema": {"type": "object", "properties": {"reason": {"type": "string"}}}}
            },
            "x-devcenter-metaData": {"mleForRequest": "optional", "mleForResponse": "mandatory"}
        })
    }

    fn spec(paths: Value) -> Value {
        json!({"swagger": "2.0", "paths": paths})
    }

    #[test]
    fn hoists_and_names_models() {
        let ir = build(
            &spec(json!({"/pts/v2/payments": {"post": payment_op()}})),
            &config(),
        )
        .unwrap();
        let names: Vec<_> = ir.models.keys().cloned().collect();
        assert_eq!(
            names,
            [
                "CreatePaymentRequest",
                "CreatePaymentRequestPaymentInformation",
                "CreatePaymentRequestPaymentInformationCard",
                "PtsV2PaymentsPost201Response",
                "PtsV2PaymentsPost201ResponseLinks",
                "PtsV2PaymentsPost201ResponseLinksSelf",
                "Ptsv2paymentsClientReferenceInformation",
            ]
        );
        let resp = &ir.models["PtsV2PaymentsPost201Response"];
        assert_eq!(resp.alias.as_deref(), Some("ptsV2PaymentsPost201Response"));
        let fields: Vec<_> = resp
            .fields
            .iter()
            .map(|f| (f.json_name.as_str(), f.rust_name.as_str()))
            .collect();
        assert_eq!(
            fields,
            [("_links", "links"), ("id", "id"), ("type", "r#type")]
        );
        assert_eq!(
            ir.models["PtsV2PaymentsPost201ResponseLinks"].fields[0].rust_name,
            "self_"
        );
    }

    #[test]
    fn maps_operation_metadata() {
        let ir = build(
            &spec(json!({"/pts/v2/payments": {"post": payment_op()}})),
            &config(),
        )
        .unwrap();
        let op = &ir.operations[0];
        assert_eq!(op.fn_name, "create_payment");
        assert_eq!(op.struct_name, "CreatePayment");
        assert_eq!(op.group, "payments");
        assert!(op.params.is_empty(), "Content-Type is a pipeline header");
        assert_eq!(op.body, Some(Ty::Model("CreatePaymentRequest".into())));
        assert_eq!(
            op.output,
            Output::Json(Ty::Model("PtsV2PaymentsPost201Response".into()))
        );
        assert_eq!(op.mle_request, Mle::Optional);
        assert_eq!(op.mle_response, Mle::Mandatory);
        assert!(!op.retry_safe);
        assert_eq!(op.doc.as_deref(), Some("Process a Payment"));
    }

    #[test]
    fn marks_sensitive_fields() {
        let ir = build(
            &spec(json!({"/pts/v2/payments": {"post": payment_op()}})),
            &config(),
        )
        .unwrap();
        let card = &ir.models["CreatePaymentRequestPaymentInformationCard"];
        assert!(
            card.fields.iter().all(|f| f.sensitive),
            "number on *Card* and securityCode"
        );
    }

    #[test]
    fn identical_schemas_with_the_same_name_merge_and_union_groups() {
        let shared =
            json!({"type": "object", "title": "Link", "properties": {"href": {"type": "string"}}});
        let op = |tag: &str, id: &str| {
            json!({
                "tags": [tag], "operationId": id,
                "responses": {"200": {"schema": {"type": "object", "title": format!("{id}Resp"), "properties": {"link": shared}}}}
            })
        };
        let ir = build(
            &spec(json!({"/a": {"get": op("payments", "getA")}, "/b": {"get": op("Customer", "getB")}})),
            &config(),
        )
        .unwrap();
        let groups: Vec<_> = ir.models["Link"].groups.iter().cloned().collect();
        assert_eq!(groups, ["payments", "tms"]);
    }

    #[test]
    fn different_schemas_with_the_same_name_are_an_error_with_a_fix() {
        let a =
            json!({"type": "object", "title": "Thing", "properties": {"a": {"type": "string"}}});
        let b =
            json!({"type": "object", "title": "thing", "properties": {"b": {"type": "string"}}});
        let op = |id: &str, s: &Value| {
            json!({
                "tags": ["payments"], "operationId": id,
                "responses": {"200": {"schema": s}}
            })
        };
        let errors = build(
            &spec(json!({"/a": {"get": op("getA", &a)}, "/b": {"get": op("getB", &b)}})),
            &config(),
        )
        .unwrap_err();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].contains("[model_renames]"), "{}", errors[0]);
        assert!(
            errors[0].contains("\"Thing@/paths/~1b/get/responses/200/schema\""),
            "{}",
            errors[0]
        );
    }

    #[test]
    fn model_renames_resolve_collisions() {
        let a =
            json!({"type": "object", "title": "Thing", "properties": {"a": {"type": "string"}}});
        let b =
            json!({"type": "object", "title": "thing", "properties": {"b": {"type": "string"}}});
        let op = |id: &str, s: &Value| json!({"tags": ["payments"], "operationId": id, "responses": {"200": {"schema": s}}});
        let mut config = config();
        config.model_renames.insert(
            "Thing@/paths/~1b/get/responses/200/schema".into(),
            "OtherThing".into(),
        );
        let ir = build(
            &spec(json!({"/a": {"get": op("getA", &a)}, "/b": {"get": op("getB", &b)}})),
            &config,
        )
        .unwrap();
        assert!(ir.models.contains_key("Thing") && ir.models.contains_key("OtherThing"));
    }

    #[test]
    fn unmapped_tags_and_missing_or_duplicate_ids_are_errors() {
        let errors = build(
            &spec(json!({
                "/a": {"get": {"tags": ["Mystery"], "operationId": "getA", "responses": {}}},
                "/b": {"get": {"tags": ["payments"], "responses": {}}},
                "/c": {"get": {"tags": ["payments"], "operationId": "dup", "responses": {}},
                       "post": {"tags": ["payments"], "operationId": "dup", "responses": {}}}
            })),
            &config(),
        )
        .unwrap_err();
        assert!(
            errors.iter().any(|e| e.contains("tag `Mystery`")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("GET /b has no operationId")),
            "{errors:?}"
        );
        assert!(
            errors.iter().any(|e| e.contains("`dup` is used by both")),
            "{errors:?}"
        );
    }

    #[test]
    fn maps_types_and_maps() {
        let schema = json!({"type": "object", "title": "T", "properties": {
            "s": {"type": "string", "format": "date-time"},
            "i": {"type": "integer", "format": "int32"},
            "l": {"type": "integer"},
            "n": {"type": "number", "format": "currency"},
            "b": {"type": "boolean"},
            "v": {},
            "free": {"type": "object"},
            "tags": {"type": "object", "additionalProperties": {"type": "string"}},
            "list": {"type": "array", "items": {"type": "object", "properties": {"x": {"type": "string"}}}}
        }});
        let ir = build(
            &spec(json!({"/t": {"get": {"tags": ["payments"], "operationId": "getT", "responses": {"200": {"schema": schema}}}}})),
            &config(),
        )
        .unwrap();
        let tys: BTreeMap<_, _> = ir.models["T"]
            .fields
            .iter()
            .map(|f| (f.json_name.as_str(), f.ty.to_string()))
            .collect();
        assert_eq!(tys["s"], "String");
        assert_eq!(tys["i"], "i32");
        assert_eq!(tys["l"], "i64");
        assert_eq!(tys["n"], "f64");
        assert_eq!(tys["b"], "bool");
        assert_eq!(tys["v"], "Value");
        assert_eq!(tys["free"], "Value");
        assert_eq!(tys["tags"], "Map<String>");
        assert_eq!(tys["list"], "Vec<TList>");
    }

    #[test]
    fn outputs_cover_unit_bytes_text_and_by_status() {
        let ops = json!({
            "/unit": {"delete": {"tags": ["payments"], "operationId": "del", "responses": {"204": {}}}},
            "/csv": {"get": {"tags": ["payments"], "operationId": "csv", "produces": ["text/csv", "application/xml"],
                     "responses": {"200": {"schema": {"type": "string"}}}}},
            "/jwt": {"post": {"tags": ["payments"], "operationId": "jwt", "produces": ["application/jwt"],
                     "responses": {"201": {"schema": {"type": "string"}}}}},
            "/jwt2": {"post": {"tags": ["payments"], "operationId": "jwtJson",
                     "responses": {"201": {"schema": {"type": "string"}}}}},
            "/multi": {"post": {"tags": ["payments"], "operationId": "multi", "responses": {
                "200": {"schema": {"type": "object", "title": "A", "properties": {"a": {"type": "string"}}}},
                "201": {"schema": {"type": "object", "title": "B", "properties": {"b": {"type": "string"}}}},
                "204": {}
            }}}
        });
        let ir = build(&spec(ops), &config()).unwrap();
        let out = |id: &str| ir.operations.iter().find(|o| o.id == id).unwrap().clone();
        assert_eq!(out("del").output, Output::Unit);
        assert_eq!(out("csv").output, Output::Bytes);
        assert_eq!(
            out("csv").accept.as_deref(),
            Some("text/csv, application/xml")
        );
        assert_eq!(out("jwt").output, Output::Text);
        assert_eq!(out("jwt").accept.as_deref(), Some("application/jwt"));
        assert_eq!(out("jwtJson").output, Output::Text);
        assert_eq!(
            out("multi").output,
            Output::ByStatus(vec![
                (200, Some(Ty::Model("A".into()))),
                (201, Some(Ty::Model("B".into()))),
                (204, None)
            ])
        );
    }

    #[test]
    fn params_are_typed_and_required_flags_kept() {
        let op = json!({"tags": ["Customer"], "operationId": "getCustomerPaymentInstruments",
            "parameters": [
                {"in": "path", "name": "customerId", "type": "string", "required": true},
                {"in": "header", "name": "profile-id", "type": "string"},
                {"in": "query", "name": "limit", "type": "integer", "format": "int64"},
                {"in": "query", "name": "startTime", "type": "string", "format": "date-time", "required": true}
            ],
            "responses": {"200": {}}});
        let ir = build(
            &spec(json!({"/tms/v2/customers/{customerId}/payment-instruments": {"get": op}})),
            &config(),
        )
        .unwrap();
        let p: Vec<_> = ir.operations[0]
            .params
            .iter()
            .map(|p| {
                (
                    p.rust_name.as_str(),
                    p.location,
                    p.ty.to_string(),
                    p.required,
                )
            })
            .collect();
        assert_eq!(
            p,
            [
                ("customer_id", ParamIn::Path, "String".into(), true),
                ("profile_id", ParamIn::Header, "String".into(), false),
                ("limit", ParamIn::Query, "i64".into(), false),
                ("start_time", ParamIn::Query, "String".into(), true),
            ]
        );
        assert!(ir.operations[0].retry_safe);
    }

    #[test]
    fn example_errata_are_classified() {
        let schema = json!({"type": "object", "properties": {
            "s": {"type": "string"},
            "n": {"type": "integer"},
            "b": {"type": "boolean"},
            "list": {"type": "array", "items": {"type": "object", "properties": {"x": {"type": "string"}}}}
        }});
        let ex = Example::new(
            "e".into(),
            json!({"s": 5, "n": "7", "b": "Y", "extra": 1, "list": [{"x": "a", "y": 2}]}),
            &schema,
        );
        assert_eq!(ex.skip, None);
        assert_eq!(ex.ignore, ["$.b", "$.extra", "$.list[0].y", "$.n", "$.s"]);

        let bad = Example::new("e".into(), json!({"n": "PHYSICAL"}), &schema);
        assert!(bad.skip.unwrap().contains("$.n"));
        let wrong_shape = Example::new("e".into(), json!({"list": {"x": "a"}}), &schema);
        assert!(wrong_shape.skip.unwrap().contains("an array"));
    }

    #[test]
    fn pagination_entries_are_validated_against_the_response() {
        let mut config = config();
        config.pagination.insert(
            "getList".into(),
            crate::codegen::config::PageSpec {
                total: "total".into(),
                count: None,
                items: Some("nope".into()),
            },
        );
        let op = json!({"tags": ["payments"], "operationId": "getList",
        "parameters": [
            {"in": "query", "name": "offset", "type": "integer", "format": "int64"},
            {"in": "query", "name": "limit", "type": "integer", "format": "int64"}
        ],
        "responses": {"200": {"schema": {"type": "object", "title": "List", "properties": {
            "total": {"type": "integer"}, "items": {"type": "array", "items": {"type": "string"}}
        }}}}});
        let errors = build(&spec(json!({"/list": {"get": op.clone()}})), &config).unwrap_err();
        assert!(errors[0].contains("`getList`"), "{errors:?}");

        config.pagination.get_mut("getList").unwrap().items = Some("items".into());
        let ir = build(&spec(json!({"/list": {"get": op}})), &config).unwrap();
        assert_eq!(
            ir.operations[0].pagination,
            Some(Pagination {
                total: "total".into(),
                count: PageCount::Items("items".into())
            })
        );
    }

    #[test]
    fn developer_id_flag_follows_the_body_schema() {
        let ir = build(
            &spec(json!({"/pts/v2/payments": {"post": payment_op()}})),
            &config(),
        )
        .unwrap();
        assert!(!ir.operations[0].developer_id);
    }

    #[test]
    fn stale_codegen_entries_are_errors() {
        let mut config = config();
        config
            .skip_operations
            .insert("POST /gone".into(), "reason".into());
        let errors = build(&spec(json!({})), &config).unwrap_err();
        assert!(errors[0].contains("`POST /gone`"), "{errors:?}");
    }

    fn body_op(id: &str, schema: Value) -> Value {
        json!({
            "tags": ["payments"], "operationId": id,
            "parameters": [{"in": "body", "name": "body", "schema": schema}],
            "responses": {"201": {}}
        })
    }

    #[test]
    fn constraints_are_read_from_properties_and_required() {
        let schema = json!({
            "type": "object", "title": "Order", "required": ["currency"],
            "properties": {
                "currency": {"type": "string", "minLength": 3, "maxLength": 3, "pattern": "^[A-Z]+$"},
                "quantity": {"type": "integer", "minimum": 1, "maximum": 999},
                "skus": {"type": "array", "maxItems": 30, "items": {"type": "string", "maxLength": 12}}
            }
        });
        let ir = build(
            &spec(json!({"/o": {"post": body_op("createOrder", schema)}})),
            &config(),
        )
        .unwrap();
        let field = |name: &str| {
            ir.models["Order"]
                .fields
                .iter()
                .find(|f| f.json_name == name)
                .unwrap()
                .constraints
                .clone()
        };
        assert_eq!(
            field("currency"),
            Constraints {
                required: true,
                min_length: Some(3),
                max_length: Some(3),
                pattern: Some("^[A-Z]+$".into()),
                ..Constraints::default()
            }
        );
        assert_eq!(
            field("quantity"),
            Constraints {
                minimum: Some(1.0),
                maximum: Some(999.0),
                ..Constraints::default()
            }
        );
        assert_eq!(
            field("skus"),
            Constraints {
                max_length: Some(12),
                max_items: Some(30),
                ..Constraints::default()
            }
        );
    }

    #[test]
    fn shared_models_keep_the_loosest_constraints() {
        let order = |max: u64, pattern: &str, required: bool| {
            let mut schema = json!({
                "type": "object", "title": "Order",
                "properties": {"code": {"type": "string", "maxLength": max, "pattern": pattern}}
            });
            if required {
                schema["required"] = json!(["code"]);
            }
            schema
        };
        let ir = build(
            &spec(json!({
                "/a": {"post": body_op("createA", order(20, "^[a-z]+$", true))},
                "/b": {"post": body_op("createB", order(50, "^[0-9]+$", false))}
            })),
            &config(),
        )
        .unwrap();
        let code = &ir.models["Order"].fields[0].constraints;
        assert_eq!(code.max_length, Some(50));
        assert_eq!(code.pattern, None, "different patterns cancel out");
        assert!(
            !code.required,
            "required only where every schema requires it"
        );
    }

    #[test]
    fn request_models_are_those_reachable_from_a_body() {
        let ir = build(
            &spec(json!({"/pts/v2/payments": {"post": payment_op()}})),
            &config(),
        )
        .unwrap();
        let names: Vec<_> = ir.request_models().into_iter().collect();
        assert_eq!(
            names,
            [
                "CreatePaymentRequest",
                "CreatePaymentRequestPaymentInformation",
                "CreatePaymentRequestPaymentInformationCard",
                "Ptsv2paymentsClientReferenceInformation",
            ]
        );
    }
}
