//! plugin/template: the `var`/`expr` tables (Corefile snippets with a
//! query and the expected rcode and sections).

use serde_json::Value;

use crate::harness::*;

/// The records of a section as text, sorted.
fn texts(v: &Value) -> Vec<String> {
    let mut out: Vec<String> = records(v).iter().map(|r| r.to_string()).collect();
    out.sort();
    out
}

pub async fn drive(r: &mut Run) {
    for id in ["TestVar/tests", "TestExpr/tests"] {
        for (row, v) in r.rows(id) {
            let tag = format!("template-{id}-{row}");
            let corefile = format!(".:53 {{\n{}\n nomad {tag} rcode REFUSED\n}}", str_of(&v["config"]));
            let res = async {
                let s = Server::try_new(&corefile).await?;
                let qtype = match u16_of(&v["qtype"]) {
                    0 => 1,
                    t => t,
                };
                let served = s.serve(question(str_of(&v["qname"]), qtype)).await;
                let want = u16_of(&v["expectedCode"]);
                if want == 3841 {
                    // rcodeFallthrough (3841): the next plugin was called
                    return if next_calls(&tag) == 1 {
                        Ok(())
                    } else {
                        Err("expected a fallthrough".to_string())
                    };
                }
                if served.code() != Some(want) {
                    return Err(format!("expected rcode {want}, got {:?}", served.rcode));
                }
                if want != 0 {
                    return Ok(());
                }
                let m = served.written().ok_or("no response")?;
                for (name, w, g) in [
                    ("answer", &v["expectedAnswer"], &m.answers),
                    ("additional", &v["expectedExtra"], &m.additionals),
                    ("authority", &v["expectedNs"], &m.authorities),
                ] {
                    let mut g: Vec<String> = g.iter().map(|r| r.to_string()).collect();
                    g.sort();
                    if texts(w) != g {
                        return Err(format!("{name}: {g:?} != {:?}", texts(w)));
                    }
                }
                Ok(())
            }
            .await;
            r.check(id, &row, res);
        }
    }
    // TestExprMatch: whether the template matches (answers) or falls through
    let id = "TestExprMatch/tests";
    for (row, v) in r.rows(id) {
        let tag = format!("template-match-{row}");
        let corefile = format!(".:53 {{\n{}\n nomad {tag} rcode REFUSED\n}}", str_of(&v["config"]));
        let res = async {
            let s = Server::try_new(&corefile).await?;
            let served = s.serve(question(str_of(&v["qname"]), 1)).await;
            let matched = served.wrote && next_calls(&tag) == 0;
            let fell = next_calls(&tag) == 1;
            if matched != v["expectedMatch"].as_bool().unwrap_or(false) {
                return Err(format!("expected match {}, got {matched}", v["expectedMatch"]));
            }
            if !matched && fell != v["expectedFthrough"].as_bool().unwrap_or(false) {
                return Err(format!("expected fallthrough {}, got {fell}", v["expectedFthrough"]));
            }
            Ok(())
        }
        .await;
        r.check(id, &row, res);
    }
}
