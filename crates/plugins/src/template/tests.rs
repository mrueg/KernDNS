use std::collections::HashMap;

use kerndns_core::CaptureWriter;
use kerndns_core::proto::op::{Message, MessageType, OpCode, Query};
use kerndns_core::proto::rr::Name;
use kerndns_core::upstream::Upstream;

use super::*;
use crate::testutil::*;

// ------------------------------------------------------------ template engine

/// Results of Go's `text/template` (go1.27) for these templates, executed
/// with the data from [`go_data`]. Generated with a small Go program that
/// mirrors `templateData`.
#[rustfmt::skip]
const GO_CASES: &[(&str, Result<&str, &str>)] = &[
        ("{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}", Ok("ip-10-95-12-8.example. 60 IN A 10.95.12.8")),
        ("{{ index .Match 2 }}|{{ index .Match 9 }}", Err("template: answer:1:24: executing \"answer\" at <index .Match 9>: error calling index: index out of range: 9")),
        ("{{ .Name }} 60 IN TXT \"{{ index .Match 5 }}\"", Err("template: answer:1:26: executing \"answer\" at <index .Match 5>: error calling index: reflect: slice index out of range")),
        ("{{ parseInt .Group.b 16 8 }}", Ok("149")),
        ("{{ .Name }} 60 IN TXT \"{{ parseInt \"gg\" 16 8 }}\"", Err("template: answer:1:26: executing \"answer\" at <parseInt \"gg\" 16 8>: error calling parseInt: strconv.ParseUint: parsing \"gg\": invalid syntax")),
        ("{{ parseInt \"300\" 10 8 }}", Err("template: answer:1:3: executing \"answer\" at <parseInt \"300\" 10 8>: error calling parseInt: strconv.ParseUint: parsing \"300\": value out of range")),
        ("{{ parseInt \"0x1f\" 0 16 }}", Ok("31")),
        ("{{ parseInt \"12\" 1 8 }}", Err("template: answer:1:3: executing \"answer\" at <parseInt \"12\" 1 8>: error calling parseInt: strconv.ParseUint: parsing \"12\": invalid base 1")),
        ("{{ parseInt }}", Err("template: answer:1:3: executing \"answer\" at <parseInt>: wrong number of args for parseInt: want 3 got 0")),
        ("{{ parseInt 12 10 8 }}", Err("template: answer:1:12: executing \"answer\" at <12>: expected string; found 12")),
        ("{{ parseInt .Group.zz 10 8 }}", Err("template: answer:1:18: executing \"answer\" at <.Group.zz>: invalid value; expected string")),
        ("{{ .Grup.d }}", Err("template: answer:1:8: executing \"answer\" at <.Grup.d>: can't evaluate field Grup in type *template.templateData")),
        ("{{ .Group.missing }}", Ok("<no value>")),
        ("{{ .Meta \"foo\" }}-{{ .Meta \"nope\" }}", Ok("myfoo-")),
        ("{{ .Meta }}", Err("template: answer:1:3: executing \"answer\" at <.Meta>: wrong number of args for Meta: want 1 got 0")),
        ("{{ if eq .Type \"A\" }}yes{{ else }}no{{ end }}", Ok("yes")),
        ("{{ if ne .Class \"IN\" }}x{{ else if eq .Group.b \"95\" }}y{{ else }}z{{ end }}", Ok("y")),
        ("a  {{- .Zone -}}  b", Ok("aexample.b")),
        ("{{/* c */}}x {{- /* c2 */ -}} y", Ok("xy")),
        ("{{ printf \"%s-%d-%05.1f-%x-%q-%v\" .Name 42 3.14159 255 \"q\" true }}", Ok("ip-10-95-12-8.example.-42-003.1-ff-\"q\"-true")),
        ("{{ printf \"%d\" \"str\" }}|{{ printf \"%s %s\" \"a\" }}|{{ printf \"%s\" \"a\" \"b\" }}", Ok("%!d(string=str)|a %!s(MISSING)|a%!(EXTRA string=b)")),
        ("{{ .Group.b | printf \"%s!\" }}", Ok("95!")),
        ("{{ (index .Message.Question 0).Name }} {{ .Message.Id }} {{ .Message.RecursionDesired }} {{ .Question.Qtype }} {{ .Message.Rcode }}", Ok("Ip-10-95-12-8.example. 4242 true 1 0")),
        ("{{ .Question }}", Ok(";Ip-10-95-12-8.example.\tIN\t A")),
        ("{{ .Match }} {{ .Group }}", Ok("[ip-10-95-12-8.example.  95 12 8] map[0:ip-10-95-12-8.example. 1: 2:95 3:12 4:8 b:95 c:12 d:8]")),
        ("{{ len .Match }} {{ len .Name }} {{ index .Name 0 }} {{ len .Group }}", Ok("5 22 105 8")),
        ("{{ and 1 0 }} {{ or 0 \"\" \"x\" }} {{ not 0 }} {{ and 1 \"y\" }} {{ or 0 \"\" }}", Ok("0 x true y ")),
        ("{{ lt 1 2 }} {{ ge \"b\" \"a\" }} {{ eq 1 2 3 1 }} {{ eq .Question.Qtype 1 }} {{ le 2 2 }} {{ gt 1 2 }}", Ok("true true true true true false")),
        ("{{ eq \"a\" 1 }}", Err("template: answer:1:3: executing \"answer\" at <eq \"a\" 1>: error calling eq: incompatible types for comparison: string and int")),
        ("{{ lt .Group.zz 1 }}", Err("template: answer:1:3: executing \"answer\" at <lt .Group.zz 1>: error calling lt: invalid type for comparison")),
        ("{{ print 1 2 \"a\" \"b\" 3 }}|{{ println 1 \"a\" }}|", Ok("1 2ab3|1 a\n|")),
        ("{{ print .Group.missing }} {{ printf \"%s\" .Group.missing }} {{ eq .Group.missing \"a\" }}", Ok("<nil> %!s(<nil>) false")),
        ("{{ 0x1F }} {{ 1.5 }} {{ -7 }} {{ 1e3 }} {{ 010 }} {{ \"a\\tb\\x41é\" }} {{ `raw` }} {{ true }}", Ok("31 1.5 -7 1000 8 a\tbAé raw true")),
        ("{{ .Var.x }}", Ok("<no value>")),
        ("{{ index .Group \"b\" }}|{{ index .Group \"zz\" }}|{{ index .Match }}", Ok("95||[ip-10-95-12-8.example.  95 12 8]")),
        ("{{ printf \"%v %v %v\" 1e21 123456789.0 0.000012 }} {{ 0.000012 }} {{ 1e20 }} {{ 100000.0 }}", Ok("1e+21 1.23456789e+08 1.2e-05 1.2e-05 1e+20 100000")),
        ("{{ printf \"%6.2f|%-6s|%+d|%x|%X|%o|%b|%c|%t\" 3.14159 \"ab\" 5 \"hi\" 255 8 5 65 false }}", Ok("  3.14|ab    |+5|6869|FF|10|101|A|false")),
        ("{{ .Name 1 }}", Err("template: answer:1:3: executing \"answer\" at <.Name>: Name has arguments but cannot be invoked as function")),
        ("{{ \"a\" \"b\" }}", Err("template: answer:1:3: executing \"answer\" at <\"a\">: can't give argument to non-function \"a\"")),
        ("{{ index .Match \"x\" }}", Err("template: answer:1:3: executing \"answer\" at <index .Match \"x\">: error calling index: cannot index slice/array with type string")),
        ("{{ len 3 }}", Err("template: answer:1:3: executing \"answer\" at <len 3>: error calling len: len of type int")),
        ("{{ printf \"%e %E %g %.3g %G\" 1234.5678 0.000123 100000000.0 3.14159 1e-7 }}", Ok("1.234568e+03 1.230000E-04 1e+08 3.14 1E-07")),
        ("{{ .Remote }} {{ .Regex }}", Ok("10.240.0.1 (^|[.])ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$")),
        ("{{ if .Group.missing }}a{{ else }}b{{ end }}", Ok("b")),
        ("{{ printf \"%5.2s|%05d|%-5d|%x|%#x|%#o|% d|%3c|%q\" \"abcdef\" -42 3 -255 255 8 5 66 66 }}", Ok("   ab|-0042|3    |-ff|0xff|010| 5|  B|'B'")),
        ("{{ printf \"%v\" .Match }} {{ printf \"%q\" .Match }} {{ printf \"%d\" .Message.Id }}", Ok("[ip-10-95-12-8.example.  95 12 8] [\"ip-10-95-12-8.example.\" \"\" \"95\" \"12\" \"8\"] 4242")),
        ("{{ index .Group.b 0 }} {{ .Group.b.x }}", Err("template: answer:1:32: executing \"answer\" at <.Group.b.x>: can't evaluate field x in type string")),
        ("{{ (index .Match 2) }}{{ (.Name) }}", Ok("95ip-10-95-12-8.example.")),
        ("{{ index .Match 2 | printf \"<%s>\" | printf \"[%s]\" }}", Ok("[<95>]")),
        ("{{ printf \"%08.3f|%-8.2f|%+.1e\" -3.14159 2.5 12345.678 }}", Ok("-003.142|2.50    |+1.2e+04")),
        ("{{ .Message.Question }}", Ok("[{Ip-10-95-12-8.example. 1 1}]")),
        ("{{ parseInt \"18446744073709551615\" 10 64 }} {{ parseInt \"18446744073709551616\" 10 0 }}", Err("template: answer:1:47: executing \"answer\" at <parseInt \"18446744073709551616\" 10 0>: error calling parseInt: strconv.ParseUint: parsing \"18446744073709551616\": value out of range")),
        ("{{ eq .Message.Id 4242 }} {{ ne .Question.Qclass 3 }}", Ok("true true")),
        ("{{ not .Group.missing }} {{ not \"\" }}", Ok("true true")),
        ("{{ if and (eq .Type \"A\") (ne .Group.b \"\") }}{{ .Group.b }}{{ end }}", Ok("95")),
        ("{{- \" x \" -}}", Ok(" x ")),
        ("{{ printf \"%%|%5%|%\" }}", Ok("%|%|%!(NOVERB)")),
        ("{{ or }}", Err("template: answer:1:3: executing \"answer\" at <or>: wrong number of args for or: want at least 1 got 0")),
];

fn go_message() -> Message {
    let mut m = Message::new(4242, MessageType::Query, OpCode::Query);
    m.metadata.recursion_desired = true;
    m.add_query(Query::query(
        Name::from_ascii("Ip-10-95-12-8.example.").unwrap(),
        RecordType::A,
    ));
    m
}

fn go_data<'a>(msg: &'a Message, meta: &'a HashMap<String, String>) -> Data<'a> {
    let matches: Vec<String> = ["ip-10-95-12-8.example.", "", "95", "12", "8"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    let mut group: HashMap<String, String> = matches
        .iter()
        .enumerate()
        .map(|(i, m)| (i.to_string(), m.clone()))
        .collect();
    group.insert("b".into(), "95".into());
    group.insert("c".into(), "12".into());
    group.insert("d".into(), "8".into());
    Data {
        zone: "example.".into(),
        name: "ip-10-95-12-8.example.".into(),
        regex: "(^|[.])ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$".into(),
        matches,
        group,
        class: "IN".into(),
        typ: "A".into(),
        message: Some(msg),
        question: Some(Question {
            name: "Ip-10-95-12-8.example.".into(),
            qtype: 1,
            qclass: 1,
        }),
        remote: "10.240.0.1".into(),
        meta: Some(meta),
    }
}

#[test]
fn engine_matches_go() {
    let msg = go_message();
    let meta: HashMap<String, String> = [("foo".to_string(), "myfoo".to_string())].into();
    let data = go_data(&msg, &meta);
    let mut failed = Vec::new();
    for (text, want) in GO_CASES {
        let got = Template::parse("answer", text).and_then(|t| t.execute(&data));
        let want = want.map(str::to_string).map_err(str::to_string);
        if got != want {
            failed.push(format!("{text}\n   got: {got:?}\n  want: {want:?}"));
        }
    }
    assert!(failed.is_empty(), "{} mismatches:\n{}", failed.len(), failed.join("\n"));
}

#[test]
fn engine_rejects_unsupported() {
    for (text, want) in [
        ("{{", "unclosed action"),
        ("{{ notAFunction }}", r#"function "notAFunction" not defined"#),
        ("{{ html .Name }}", r#"function "html" is not supported"#),
        ("{{ if .Name }}x", "unexpected EOF"),
        ("{{ end }}", "unexpected {{end}}"),
        ("{{ else }}", "unexpected {{else}}"),
        ("{{ range .Match }}{{ end }}", "{{range}} is not supported"),
        ("{{ with .Name }}{{ end }}", "{{with}} is not supported"),
        (r#"{{ define "x" }}{{ end }}"#, "{{define}} is not supported"),
        (r#"{{ template "x" }}"#, "{{template}} is not supported"),
        ("{{ $x := .Name }}", "variables ($) are not supported"),
        ("{{ 'a' }}", "character constants are not supported"),
        (
            "{{ .Message }}",
            "printing or passing the whole .Message is not supported",
        ),
        ("{{ .Message.Answer }}", ".Message.Answer is not supported"),
        ("{{ .Question.Foo }}", ".Question.Foo is not supported"),
        ("{{ . }}", "the dot (.) on its own is not supported"),
        (r#"{{ printf "%[1]s" .Name }}"#, "is not supported"),
        (r#"{{ printf "%U" 1 }}"#, "verb %U"),
        ("{{ .Name | 1 }}", "non executable command in pipeline stage 2"),
        ("{{ nil }}", "nil is not a command"),
        ("{{ (.Name }}", "unclosed left paren"),
        ("{{}}", "missing value for command"),
        ("{{ 1.Name }}", "bad number syntax"),
        (r#"{{ "x }}"#, "unterminated quoted string"),
        ("{{/* x }}", "unclosed comment"),
    ] {
        let err = Template::parse("answer", text).expect_err(text);
        assert!(err.starts_with("template: answer:1: "), "{text}: {err}");
        assert!(err.contains(want), "{text}: {err} does not contain {want}");
    }
}

#[test]
fn engine_string_form() {
    // Go's Tree.Root.String(), used as the "template" metric label.
    let t = Template::parse(
        "answer",
        r#"{{ .Name }} 60 IN A {{- if eq .Type "A" }} {{ index .Match 1 | printf "%s" }}{{ else if .Zone }}x{{ else }}y{{ end }}{{/* c */}}"#,
    )
    .unwrap();
    assert_eq!(
        t.to_string(),
        r#"{{.Name}} 60 IN A{{if eq .Type "A"}} {{index .Match 1 | printf "%s"}}{{else}}{{if .Zone}}x{{else}}y{{end}}{{end}}"#
    );
}

#[test]
fn engine_multiline_positions() {
    let msg = go_message();
    let meta = HashMap::new();
    let data = go_data(&msg, &meta);
    let t = Template::parse("answer", "a\n  {{ index .Match 7 }}").unwrap();
    assert_eq!(
        t.execute(&data).unwrap_err(),
        r#"template: answer:2:5: executing "answer" at <index .Match 7>: error calling index: index out of range: 7"#
    );
}

// -------------------------------------------------------------------- setup

fn parse_with_keys(directive: &str, keys: &str) -> Result<(Vec<String>, Vec<Tmpl>), String> {
    use kerndns_core::corefile::{Dispenser, parse};
    use kerndns_core::{BlockConfig, Hooks, ZoneAddr};
    let blocks = parse(&format!("{keys} {{\n{directive}\n}}"), "Corefile").expect("parses");
    let mut cfg = BlockConfig::new(
        keys.split_whitespace()
            .flat_map(|k| ZoneAddr::parse(k, "53").unwrap())
            .collect(),
    );
    let mut hooks = Hooks::default();
    let mut c = Controller::new(
        "template",
        Dispenser::new(blocks[0].tokens_for("template")),
        &mut cfg,
        &mut hooks,
        ".".into(),
    );
    template_parse(&mut c).map_err(|e| e.to_string())
}

#[test]
fn setup() {
    assert!(setup_err(&Setup, "template ANY ANY {\n rcode\n}").contains("Wrong argument count"));
    assert!(setup_ok(&Setup, "template ANY ANY {\n rcode NXDOMAIN\n}"));
}

#[test]
fn setup_parse() {
    let keys = "domain.com.:8053 dynamic.domain.com.:8053";
    let cases: &[(&str, bool)] = &[
        ("template", true),
        ("template X", true),
        ("template ANY", true),
        ("template ANY X", true),
        ("template ANY ANY .* {\n notavailable\n}", true),
        ("template ANY ANY {\n answer\n}", true),
        ("template ANY ANY {\n additional\n}", true),
        ("template ANY ANY {\n rcode\n}", true),
        ("template ANY ANY {\n rcode UNDEFINED\n}", true),
        ("template ANY ANY {\n answer \"{{\"\n}", true),
        ("template ANY ANY {\n additional \"{{\"\n}", true),
        ("template ANY ANY {\n authority \"{{\"\n}", true),
        ("template ANY ANY {\n answer \"{{ notAFunction }}\"\n}", true),
        (
            "template ANY ANY {\n answer \"{{ parseInt }}\"\n additional \"{{ parseInt }}\"\n authority \"{{ parseInt }}\"\n}",
            false,
        ),
        ("template ANY ANY (?P<x>", false),
        ("template ANY ANY {\n\n}", false),
        (
            "template ANY A example.com {\n match ip-(?P<a>[0-9]*)-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]com\n answer \"{{ .Name }} A {{ .Group.a }}.{{ .Group.b }}.{{ .Group.c }}.{{ .Grup.d }}.\"\n fallthrough\n}",
            false,
        ),
        (
            "template ANY AAAA example.com {\n match ip-(?P<a>[0-9]*)-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]com\n authority \"example.com 60 IN SOA ns.example.com hostmaster.example.com (1 60 60 60 60)\"\n fallthrough\n}",
            false,
        ),
        (
            "template IN ANY example.com {\n match \"[.](example[.]com[.]dc1[.]example[.]com[.])$\"\n rcode NXDOMAIN\n authority \"{{ index .Match 1 }} 60 IN SOA ns.{{ index .Match 1 }} hostmaster.example.com (1 60 60 60 60)\"\n fallthrough example.com\n}",
            false,
        ),
        (
            "template IN A example {\n match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$\n answer \"{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}\"\n}\ntemplate IN MX example. {\n match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$\n answer \"{{ .Name }} 60 IN MX 10 {{ .Name }}\"\n additional \"{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}\"\n}",
            false,
        ),
        (
            "template IN A example {\n match ^ip0a(?P<b>[a-f0-9]{2})(?P<c>[a-f0-9]{2})(?P<d>[a-f0-9]{2})[.]example[.]$\n answer \"{{ .Name }} 3600 IN A 10.{{ parseInt .Group.b 16 8 }}.{{ parseInt .Group.c 16 8 }}.{{ parseInt .Group.d 16 8 }}\"\n}",
            false,
        ),
        (
            "template ANY ANY invalid {\n rcode NXDOMAIN\n authority \"invalid. 60 {{ .Class }} SOA ns.invalid. hostmaster.invalid. (1 60 60 60 60)\"\n ederror 21 \"Blocked according to RFC2606\"\n}",
            false,
        ),
        (
            "template ANY ANY invalid {\n rcode NXDOMAIN\n ederror invalid \"Blocked according to RFC2606\"\n}",
            true,
        ),
        ("template ANY ANY invalid {\n ederror too many arguments\n}", true),
        ("template ANY ANY invalid {\n ederror 65536\n}", true),
        ("template ANY ANY {\n match (\n}", true),
        ("template ANY ANY {\n upstream\n}", false),
        ("template ANY ANY {\n upstream 8.8.8.8\n}", false),
        // the expr language is not ported
        ("template ANY ANY example. {\n var a 1\n}", true),
        ("template ANY ANY example. {\n expr name() == 'a.example.'\n}", true),
    ];
    for (i, (input, should_err)) in cases.iter().enumerate() {
        let res = parse_with_keys(input, keys);
        assert_eq!(res.is_err(), *should_err, "case {i}: {input}\n{:?}", res.err());
    }

    let (zones, ts) = parse_with_keys("template IN A {\n}\ntemplate CH TXT coredns.invalid {\n}", keys).unwrap();
    assert_eq!(zones, ["domain.com.", "dynamic.domain.com.", "coredns.invalid."]);
    assert_eq!(ts.len(), 2);
    assert_eq!(ts[0].regex[0].as_str(), ".*");
    assert_eq!(ts[1].qclass, DNSClass::CH);
    assert_eq!(ts[1].qtype, RecordType::TXT);

    let err = parse_with_keys("template ANY ANY {\n var a 1\n}", keys).unwrap_err();
    assert!(err.contains("var is not supported"), "{err}");
    let err = parse_with_keys("template ANY ANY {\n answer \"{{ range .Match }}{{ end }}\"\n}", keys).unwrap_err();
    assert!(
        err.contains("could not compile template") && err.contains("{{range}} is not supported"),
        "{err}"
    );
    let err = parse_with_keys("template ANY ANY {\n rcode UNDEFINED\n}", keys).unwrap_err();
    assert!(err.contains("unknown rcode UNDEFINED"), "{err}");
    let err = parse_with_keys("template FOO ANY", keys).unwrap_err();
    assert!(err.contains("invalid query class FOO"), "{err}");
    let err = parse_with_keys("template IN FOO", keys).unwrap_err();
    assert!(err.contains("invalid RR class FOO"), "{err}");
}

#[test]
fn setup_parse_large_regex() {
    let re = "a".repeat(MAX_REGEXP_LEN + 1);
    let err = parse_with_keys(&format!("template ANY A example.com {{\n match {re}\n}}"), ".:53").unwrap_err();
    assert!(err.contains("too long"), "{err}");
}

// ------------------------------------------------------------------ handler

const RCODE_FALLTHROUGH: u16 = 3841;

struct NextHandler;

#[async_trait]
impl Handler for NextHandler {
    fn name(&self) -> &'static str {
        "next"
    }
    async fn serve_dns(&self, _: &mut Context, _: &mut dyn ResponseWriter, _: &Request) -> HandlerResult {
        Ok(ResponseCode::Unknown(RCODE_FALLTHROUGH))
    }
}

fn base(re: &str) -> Tmpl {
    let mut fall = Fall::default();
    fall.set_zones_from_args(&[]);
    Tmpl {
        zones: vec![".".into()],
        rcode: ResponseCode::NoError,
        regex: vec![Regex::new(re).unwrap()],
        answer: Vec::new(),
        additional: Vec::new(),
        authority: Vec::new(),
        qclass: DNSClass::ANY,
        qtype: RecordType::ANY,
        ederror: None,
        fall,
    }
}

fn tpls(section: &str, texts: &[&str]) -> Vec<Template> {
    texts.iter().map(|t| Template::parse(section, t).unwrap()).collect()
}

fn handler(templates: Vec<Tmpl>) -> TemplateHandler {
    TemplateHandler {
        zones: Arc::new(vec![".".into()]),
        templates: Arc::new(templates),
        next: Some(Arc::new(NextHandler)),
    }
}

async fn run(h: &TemplateHandler, ctx: &mut Context, name: &str, qtype: RecordType) -> (HandlerResult, CaptureWriter) {
    let req = query(name, qtype, "10.240.0.1:40212");
    let mut w = CaptureWriter::new();
    let rc = h.serve_dns(ctx, &mut w, &req).await;
    (rc, w)
}

async fn serve_one(t: Tmpl, name: &str, qtype: RecordType) -> (HandlerResult, CaptureWriter) {
    let mut ctx = Context::new(".", "dns://:53");
    run(&handler(vec![t]), &mut ctx, name, qtype).await
}

const IP_RE: &str = "(^|[.])ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$";
const IP_A: &str = "{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}";

fn rdata_str(r: &Record) -> String {
    r.data.to_string()
}

#[tokio::test]
async fn rcode_servfail() {
    let mut t = base(".*");
    t.rcode = ResponseCode::ServFail;
    let (rc, w) = serve_one(t, "test.invalid.", RecordType::A).await;
    assert_eq!(rc.unwrap(), ResponseCode::ServFail);
    assert!(w.msg().is_none());
}

#[tokio::test]
async fn name_mismatch_falls_through() {
    let mut t = base(IP_RE);
    t.answer = tpls("answer", &[IP_A]);
    let (rc, _) = serve_one(t, "test.invalid.", RecordType::A).await;
    assert_eq!(rc.unwrap(), ResponseCode::Unknown(RCODE_FALLTHROUGH));
}

#[tokio::test]
async fn broken_templates() {
    let mut t = base("[.]example[.]$");
    t.answer = tpls("answer", &["{{ .Name }} 60 IN TXT \"{{ index .Match 2 }}\""]);
    let err = serve_one(t, "test.example.", RecordType::ANY).await.0.unwrap_err();
    assert_eq!(err.rcode, ResponseCode::ServFail);
    assert_eq!(
        err.msg,
        r#"template: answer:1:26: executing "answer" at <index .Match 2>: error calling index: index out of range: 2"#
    );

    let mut t = base("[.]example[.]$");
    t.answer = tpls("answer", &["{{ .Name }} 60 IN TXT \"{{ parseInt \"gg\" 16 8 }}\""]);
    let err = serve_one(t, "test.example.", RecordType::ANY).await.0.unwrap_err();
    assert_eq!(
        err.msg,
        r#"template: answer:1:26: executing "answer" at <parseInt "gg" 16 8>: error calling parseInt: strconv.ParseUint: parsing "gg": invalid syntax"#
    );

    for section in ["answer", "additional", "authority"] {
        let mut t = base("[.]example[.]$");
        let tp = tpls(section, &["{{ .Name }}"]);
        match section {
            "answer" => t.answer = tp,
            "additional" => t.additional = tp,
            _ => t.authority = tp,
        }
        let (rc, w) = serve_one(t, "test.example.", RecordType::ANY).await;
        assert!(rc.unwrap_err().msg.starts_with("dns: "), "{section}");
        assert!(w.msg().is_none());
    }
}

#[tokio::test]
async fn answers() {
    // .Remote
    let mut t = base(".*");
    t.qclass = DNSClass::IN;
    t.qtype = RecordType::A;
    t.answer = tpls("answer", &["{{ .Name }} 60 IN A {{ .Remote }}"]);
    let (rc, w) = serve_one(t, "test.example.", RecordType::A).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    let m = w.msg().unwrap();
    assert!(m.metadata.authoritative);
    assert_eq!(m.answers.len(), 1);
    assert_eq!(rdata_str(&m.answers[0]), "10.240.0.1");

    // named groups
    let mut t = base(IP_RE);
    t.answer = tpls("answer", &[IP_A]);
    let (_, w) = serve_one(t, "ip-10-95-12-8.example.", RecordType::A).await;
    let m = w.msg().unwrap();
    assert_eq!(m.answers[0].name.to_ascii(), "ip-10-95-12-8.example.");
    assert_eq!(m.answers[0].ttl, 60);
    assert_eq!(rdata_str(&m.answers[0]), "10.95.12.8");

    // parseInt
    let mut t = base("^ip0a(?P<b>[a-f0-9]{2})(?P<c>[a-f0-9]{2})(?P<d>[a-f0-9]{2})[.]example[.]$");
    t.answer = tpls(
        "answer",
        &[
            "{{ .Name }} 60 IN A 10.{{ parseInt .Group.b 16 8 }}.{{ parseInt .Group.c 16 8 }}.{{ parseInt .Group.d 16 8 }}",
        ],
    );
    let (_, w) = serve_one(t, "ip0a5f0c09.example.", RecordType::A).await;
    assert_eq!(rdata_str(&w.msg().unwrap().answers[0]), "10.95.12.9");

    // MX with additional
    let mut t = base(IP_RE);
    t.answer = tpls("answer", &["{{ .Name }} 60 MX 10 {{ .Name }}"]);
    t.additional = tpls("additional", &[IP_A]);
    let (_, w) = serve_one(t, "ip-10-95-12-8.example.", RecordType::MX).await;
    let m = w.msg().unwrap();
    assert_eq!(m.answers[0].record_type(), RecordType::MX);
    assert_eq!(m.additionals.len(), 1);
    assert_eq!(m.additionals[0].record_type(), RecordType::A);

    // additional and authority without TTL (NewRR's default 3600)
    let mut t = base(IP_RE);
    t.answer = tpls("answer", &[IP_A]);
    t.additional = tpls("additional", &["ns0.example. IN A 203.0.113.8"]);
    t.authority = tpls("authority", &["example. IN NS ns0.example.com."]);
    let (_, w) = serve_one(t, "ip-10-95-12-8.example.", RecordType::A).await;
    let m = w.msg().unwrap();
    assert_eq!(m.answers.len(), 1);
    assert_eq!(m.additionals.len(), 1);
    assert_eq!(m.authorities.len(), 1);
    assert_eq!(m.authorities[0].record_type(), RecordType::NS);
    assert_eq!(m.authorities[0].ttl, 3600);

    // NXDOMAIN with an SOA in the answer
    let mut t = base("[.]invalid[.]$");
    t.rcode = ResponseCode::NXDomain;
    t.answer = tpls(
        "answer",
        &["invalid. 60 {{ .Class }} SOA a.invalid. b.invalid. (1 60 60 60 60)"],
    );
    let (rc, w) = serve_one(t, "test.invalid.", RecordType::MX).await;
    assert_eq!(rc.unwrap(), ResponseCode::NXDomain);
    let m = w.msg().unwrap();
    assert_eq!(m.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(m.answers[0].record_type(), RecordType::SOA);

    // a CNAME without an upstream server: just the CNAME
    let mut t = base("example[.]net[.]");
    t.answer = tpls("answer", &["example.net 60 IN CNAME target.example.com"]);
    let (rc, w) = serve_one(t, "example.net.", RecordType::A).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    let m = w.msg().unwrap();
    assert_eq!(m.answers.len(), 1);
    assert_eq!(rdata_str(&m.answers[0]), "target.example.com.");
}

#[tokio::test]
async fn metadata() {
    let mut t = base(IP_RE);
    t.answer = tpls(
        "answer",
        &[r#"{{ .Meta "foo" }}-{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"#],
    );
    t.additional = tpls("additional", &[r#"{{ .Meta "bar" }}.example. IN A 203.0.113.8"#]);
    t.authority = tpls("authority", &[r#"example. IN NS {{ .Meta "bar" }}.example.com."#]);
    let mut ctx = Context::new(".", "dns://:53");
    for (k, v) in [("foo", "myfoo"), ("bar", "mybar"), ("foobar", "myfoobar")] {
        ctx.metadata.insert(k.into(), v.into());
    }
    let (_, w) = run(&handler(vec![t]), &mut ctx, "ip-10-95-12-8.example.", RecordType::A).await;
    let m = w.msg().unwrap();
    assert_eq!(m.answers[0].name.to_ascii(), "myfoo-ip-10-95-12-8.example.");
    assert_eq!(m.additionals[0].name.to_ascii(), "mybar.example.");
    assert_eq!(rdata_str(&m.authorities[0]), "mybar.example.com.");

    let mut t = base(IP_RE);
    t.answer = tpls(
        "answer",
        &[r#"{{ .Meta "foofoo" }}{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"#],
    );
    let mut ctx = Context::new(".", "dns://:53");
    ctx.metadata.insert("foo".into(), "myfoo".into());
    let (_, w) = run(&handler(vec![t]), &mut ctx, "ip-10-95-12-8.example.", RecordType::A).await;
    assert_eq!(w.msg().unwrap().answers[0].name.to_ascii(), "ip-10-95-12-8.example.");
}

#[tokio::test]
async fn extended_error() {
    let mut t = base(".*");
    t.rcode = ResponseCode::NXDomain;
    t.authority = tpls(
        "authority",
        &["invalid. 60 {{ .Class }} SOA ns.invalid. hostmaster.invalid. (1 60 60 60 60)"],
    );
    t.ederror = Some((21, "Blocked due to RFC2606".into()));
    let (rc, w) = serve_one(t, "test.invalid.", RecordType::A).await;
    assert_eq!(rc.unwrap(), ResponseCode::NXDomain);
    let m = w.msg().unwrap();
    let edns = m.edns.as_ref().expect("EDNS enabled");
    assert_eq!(edns.max_payload(), 4096);
    assert!(edns.flags().dnssec_ok);
    let mut want = 21u16.to_be_bytes().to_vec();
    want.extend_from_slice(b"Blocked due to RFC2606");
    assert_eq!(
        edns.option(kerndns_core::proto::rr::rdata::opt::EdnsCode::Unknown(EDNS0_EDE)),
        Some(&EdnsOption::Unknown(EDNS0_EDE, want))
    );
}

struct Upstub;

#[async_trait]
impl Upstream for Upstub {
    async fn lookup(
        &self,
        _: &Context,
        _: &Request,
        name: &Name,
        _: RecordType,
    ) -> Result<Option<Message>, PluginError> {
        assert_eq!(name.to_ascii(), "test.up.");
        let mut m = Message::new(0, MessageType::Response, OpCode::Query);
        m.metadata.truncation = true;
        m.answers.push(new_rr("test.up. 600 IN A 1.2.3.4").unwrap().unwrap());
        Ok(Some(m))
    }
}

#[tokio::test]
async fn truncated_cname() {
    let mut t = base(r"^cname\.test\.$");
    t.zones = vec!["test.".into()];
    t.qclass = DNSClass::IN;
    t.qtype = RecordType::A;
    t.answer = tpls("answer", &["cname.test. 600 IN CNAME test.up."]);
    let mut ctx = Context::new(".", "dns://:53");
    ctx.upstream = Some(Arc::new(Upstub));
    let (rc, w) = run(&handler(vec![t]), &mut ctx, "cname.test.", RecordType::A).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    let m = w.msg().unwrap();
    assert!(m.metadata.truncation, "reply marked truncated");
    assert_eq!(m.answers.len(), 2);
    assert_eq!(m.answers[0].record_type(), RecordType::CNAME);
    assert_eq!(rdata_str(&m.answers[1]), "1.2.3.4");
}

#[tokio::test]
async fn multi_section() {
    let config = r#"
        template IN A {
            rcode REFUSED
        }
        template IN TXT {
            match "$^"
            rcode SERVFAIL
            fallthrough
        }
        template CH TXT coredns.invalid {
            answer "{{ .Name }} 60 CH TXT \"test\""
        }
        template IN A example {
            match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$
            answer "{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"
            fallthrough
        }
        template IN MX example {
            match ^ip-10-(?P<b>[0-9]*)-(?P<c>[0-9]*)-(?P<d>[0-9]*)[.]example[.]$
            answer "{{ .Name }} 60 IN MX 10 {{ .Name }}"
            additional "{{ .Name }} 60 IN A 10.{{ .Group.b }}.{{ .Group.c }}.{{ .Group.d }}"
        }"#;
    let (zones, templates) = parse_with_keys(config, "test.:8053").unwrap();
    let h = TemplateHandler {
        zones: Arc::new(zones),
        templates: Arc::new(templates),
        next: Some(Arc::new(NextHandler)),
    };
    let mut ctx = Context::new(".", "dns://:53");
    let fall = ResponseCode::Unknown(RCODE_FALLTHROUGH);

    let (rc, _) = run(&h, &mut ctx, "some.test.", RecordType::A).await;
    assert_eq!(rc.unwrap(), ResponseCode::Refused);
    let (rc, _) = run(&h, &mut ctx, "some.test.", RecordType::TXT).await;
    assert_eq!(rc.unwrap(), fall);

    let mut req = query("coredns.invalid.", RecordType::TXT, "10.240.0.1:40212");
    req.msg.queries[0].set_query_class(DNSClass::CH);
    let mut w = CaptureWriter::new();
    let rc = h.serve_dns(&mut ctx, &mut w, &req).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    let m = w.msg().unwrap();
    assert_eq!(m.answers.len(), 1);
    assert_eq!(rdata_str(&m.answers[0]), "test");
    assert_eq!(m.answers[0].dns_class, DNSClass::CH);

    let (rc, w) = run(&h, &mut ctx, "ip-10-11-12-13.example.", RecordType::A).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    assert_eq!(w.msg().unwrap().answers[0].record_type(), RecordType::A);
    let (rc, w) = run(&h, &mut ctx, "ip-10-11-12-13.example.", RecordType::MX).await;
    assert_eq!(rc.unwrap(), ResponseCode::NoError);
    assert_eq!(w.msg().unwrap().answers[0].record_type(), RecordType::MX);

    let (rc, _) = run(&h, &mut ctx, "something.example.", RecordType::A).await;
    assert_eq!(rc.unwrap(), fall);
    let (rc, _) = run(&h, &mut ctx, "something.example.", RecordType::MX).await;
    assert_eq!(rc.unwrap(), ResponseCode::ServFail);
}

#[tokio::test]
async fn metrics() {
    let mut t = base(IP_RE);
    t.answer = tpls("answer", &["{{ .Name }} 60 IN A {{ .Group.zz }}"]);
    let mut ctx = Context::new(".", "dns://:5300");
    let res = run(&handler(vec![t]), &mut ctx, "ip-10-1-2-3.example.", RecordType::A)
        .await
        .0;
    assert!(res.is_err());
    let matched = pm::TEMPLATE_MATCHES
        .with_label_values(&["dns://:5300", ".", "", "IN", "A"])
        .get();
    assert!(matched >= 1.0);
    let rr_fail = pm::TEMPLATE_RR_FAILURES
        .with_label_values(&[
            "dns://:5300",
            ".",
            "",
            "IN",
            "A",
            "answer",
            "{{.Name}} 60 IN A {{.Group.zz}}",
        ])
        .get();
    assert!(rr_fail >= 1.0);
}
