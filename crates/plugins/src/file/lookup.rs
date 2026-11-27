//! The answer algorithm of `plugin/file/lookup.go` (with `closest.go`,
//! `wildcard.go` and `dname.go`): delegations, CNAME chasing (internally
//! and through the server for out-of-zone targets), DNAME synthesis,
//! wildcards with RFC 4592 empty-non-terminal rules, NSEC denial and
//! additional-section processing.

use std::collections::HashSet;

use kerndns_core::proto::op::ResponseCode;
use kerndns_core::proto::rr::rdata::CNAME;
use kerndns_core::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use kerndns_core::upstream::{self, MAX_LOOP};
use kerndns_core::{Context, Request};

use super::zone::{Elem, Tree, Zone, ZoneData, label_count, sub_type_signature};
use super::zonefile::{DNAME, dname_target};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupResult {
    Success,
    NameError,
    Delegation,
    NoData,
    ServerFailure,
}

/// Answer, authority and additional sections plus the outcome.
pub type Lookup = (Vec<Record>, Vec<Record>, Vec<Record>, LookupResult);

fn fail() -> Lookup {
    (Vec::new(), Vec::new(), Vec::new(), LookupResult::ServerFailure)
}

/// `typeFromElem`: records of `t` plus (with DO) their signatures.
fn type_from_elem(e: &Elem, t: RecordType, do_bit: bool) -> Vec<Record> {
    let mut v = e.typ(t).to_vec();
    if do_bit {
        v.extend(sub_type_signature(e.typ(RecordType::RRSIG), t));
    }
    v
}

/// `*.` + the parent of `name`; `None` for the root.
fn wildcard_of(name: &Name) -> Option<Name> {
    if name.is_root() {
        return None;
    }
    name.base_name().prepend_label("*").ok()
}

/// A name in the tree is strictly below `name`.
fn has_descendant(tr: &Tree, name: &Name) -> bool {
    tr.next_after(name).is_some_and(|e| name.zone_of(e.name()))
}

/// RFC 4592: a wildcard doesn't apply if an empty non-terminal exists
/// between it and the query name.
fn closer_ent_exists(tr: &Tree, qname: &Name, wildcard: &Name) -> bool {
    if !wildcard.is_wildcard() {
        return false;
    }
    let parent = wildcard.base_name();
    let mut name = qname.clone();
    while !name.is_root() {
        name = name.base_name();
        if name == parent || !parent.zone_of(&name) {
            return false;
        }
        if has_descendant(tr, &name) {
            return true;
        }
    }
    false
}

fn cname_target(r: &Record) -> Option<&Name> {
    match &r.data {
        RData::CNAME(c) => Some(&c.0),
        _ => None,
    }
}

/// `synthesizeCNAME`: the CNAME a DNAME at `owner` implies for `qname`.
fn synthesize_cname(qname: &Name, dname: &Record) -> Option<Record> {
    let target = dname_target(dname)?;
    let owner = &dname.name;
    if !owner.zone_of(qname) || qname == owner {
        return None;
    }
    let keep = label_count(qname) - label_count(owner);
    let mut labels: Vec<Vec<u8>> = qname.iter().take(keep).map(<[u8]>::to_vec).collect();
    labels.extend(target.iter().map(<[u8]>::to_vec));
    let mut new = Name::from_labels(labels).ok()?;
    new.set_fqdn(true);
    let mut r = Record::from_rdata(qname.clone(), dname.ttl, RData::CNAME(CNAME(new)));
    r.dns_class = DNSClass::IN;
    Some(r)
}

/// Run a future that recurses back into lookup, boxed to break the cycle.
type BoxFut<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

impl Zone {
    /// `Zone.Lookup`.
    pub fn lookup<'a>(&'a self, ctx: &'a Context, req: &'a Request, qname: &'a Name) -> BoxFut<'a, Lookup> {
        Box::pin(async move {
            let qtype = req.qtype();
            let do_bit = req.do_bit();
            let data = self.snapshot();
            let ap = &data.apex;
            let tr = &data.tree;
            if ap.soa.is_none() {
                return fail();
            }

            if *qname == self.origin {
                match qtype {
                    RecordType::SOA => return (ap.soa(do_bit), ap.ns(do_bit), Vec::new(), LookupResult::Success),
                    RecordType::NS => {
                        let ns = ap.ns(do_bit);
                        let glue = tr.glue(&ns, do_bit);
                        return (ns, Vec::new(), glue, LookupResult::Success);
                    }
                    _ => {}
                }
            }

            if ctx.loop_count > MAX_LOOP {
                return fail();
            }

            let mut found = false;
            let mut shot;
            let mut elem: Option<&Elem> = None;
            let mut wild_elem: Option<&Elem> = None;
            let mut wild_name: Option<Name> = None;
            let mut i = 0;
            loop {
                let parts;
                (parts, shot) = self.name_from_right(qname, i);
                if shot {
                    break;
                }
                match tr.search(&parts) {
                    None => {
                        found = false;
                        elem = None;
                        if let Some(wc) = wildcard_of(&parts) {
                            if let Some(w) = tr.search(&wc) {
                                wild_elem = Some(w);
                                wild_name = Some(w.name().clone());
                            } else if has_descendant(tr, &wc) {
                                wild_elem = None;
                                wild_name = Some(wc);
                            }
                        }
                        i += 1;
                        continue;
                    }
                    Some(e) => {
                        found = true;
                        elem = Some(e);
                    }
                }
                let e = elem.unwrap();

                // DNAME: synthesize a CNAME and follow it
                if let Some(dname) = e.typ(DNAME).first()
                    && let Some(cname) = synthesize_cname(&req.qname().to_lowercase(), dname)
                {
                    if cname_target(&cname).is_some_and(|t| *t == cname.name) {
                        return fail();
                    }
                    let (answer, ns, extra, rc) = if qtype == RecordType::CNAME {
                        (vec![cname], ap.ns(do_bit), Vec::new(), LookupResult::Success)
                    } else {
                        let mut c2 = ctx.clone();
                        c2.loop_count += 1;
                        self.external_lookup(&c2, req, &data, e, vec![cname]).await
                    };
                    let mut out = e.typ(DNAME).to_vec();
                    if do_bit {
                        out.extend(sub_type_signature(e.typ(RecordType::RRSIG), DNAME));
                    }
                    out.extend(answer);
                    return (out, ns, extra, rc);
                }

                if let Some((ns, glue)) = delegation_from_elem(tr, e, qname, qtype, do_bit) {
                    return (Vec::new(), ns, glue, LookupResult::Delegation);
                }
                i += 1;
            }

            if found && shot {
                let e = elem.unwrap();
                let cnames = e.typ(RecordType::CNAME);
                if !cnames.is_empty() && qtype != RecordType::CNAME {
                    let mut c2 = ctx.clone();
                    c2.loop_count += 1;
                    return self.external_lookup(&c2, req, &data, e, cnames.to_vec()).await;
                }
                let mut rrs = e.typ(qtype).to_vec();
                if rrs.is_empty() {
                    let mut ret = ap.soa(do_bit);
                    if do_bit {
                        ret.extend(type_from_elem(e, RecordType::NSEC, do_bit));
                    }
                    return (Vec::new(), ret, Vec::new(), LookupResult::NoData);
                }
                let additional = self.additional_processing(&data, &rrs, do_bit);
                if do_bit {
                    rrs.extend(sub_type_signature(e.typ(RecordType::RRSIG), qtype));
                }
                return (rrs, ap.ns(do_bit), additional, LookupResult::Success);
            }

            // Wildcard, unless an empty non-terminal is closer (RFC 4592).
            if let Some(wname) = &wild_name
                && !closer_ent_exists(tr, qname, wname)
            {
                let Some(w) = wild_elem else {
                    return (Vec::new(), ap.soa(do_bit), Vec::new(), LookupResult::NoData);
                };
                let cnames = w.type_for_wildcard(RecordType::CNAME, qname);
                if !cnames.is_empty() && qtype != RecordType::CNAME {
                    let mut c2 = ctx.clone();
                    c2.loop_count += 1;
                    return self.external_lookup(&c2, req, &data, w, cnames).await;
                }
                let mut rrs = w.type_for_wildcard(qtype, qname);
                if rrs.is_empty() {
                    let mut ret = ap.soa(do_bit);
                    if do_bit {
                        ret.extend(type_from_elem(w, RecordType::NSEC, do_bit));
                    }
                    return (Vec::new(), ret, Vec::new(), LookupResult::NoData);
                }
                let additional = self.additional_processing(&data, &rrs, do_bit);
                let mut auth = ap.ns(do_bit);
                if do_bit {
                    if let Some(deny) = tr.prev(qname) {
                        auth.extend(type_from_elem(deny, RecordType::NSEC, do_bit));
                    }
                    let sigs = w.type_for_wildcard(RecordType::RRSIG, qname);
                    rrs.extend(sub_type_signature(&sigs, qtype));
                }
                return (rrs, auth, additional, LookupResult::Success);
            }

            // Name error, or NODATA for an empty non-terminal.
            let rcode = if has_descendant(tr, qname) {
                LookupResult::Success
            } else {
                LookupResult::NameError
            };
            let mut ret = ap.soa(do_bit);
            if do_bit && let Some(deny) = tr.prev(qname) {
                ret.extend(type_from_elem(deny, RecordType::NSEC, do_bit));
                if rcode == LookupResult::NameError
                    && let Some(ce) = closest_encloser(self, tr, qname)
                    && let Ok(wc) = ce.name().prepend_label("*")
                    && let Some(ss) = tr.prev(&wc)
                    && ss.name() != deny.name()
                {
                    ret.extend(type_from_elem(ss, RecordType::NSEC, do_bit));
                }
            }
            (Vec::new(), ret, Vec::new(), rcode)
        })
    }

    /// `externalLookup`: follow a CNAME chain inside the zone, handing
    /// out-of-zone targets to the server.
    fn external_lookup<'a>(
        &'a self,
        ctx: &'a Context,
        req: &'a Request,
        data: &'a ZoneData,
        elem: &'a Elem,
        mut rrs: Vec<Record>,
    ) -> BoxFut<'a, Lookup> {
        Box::pin(async move {
            let qtype = req.qtype();
            let do_bit = req.do_bit();
            let tr = &data.tree;
            if do_bit {
                rrs.extend(sub_type_signature(elem.typ(RecordType::RRSIG), RecordType::CNAME));
            }

            let mut target = match rrs.first().and_then(cname_target) {
                Some(t) => t.clone(),
                None => return fail(),
            };
            let mut elem = tr.search(&target);
            let mut hops = 0;
            loop {
                if let Some((ns, extra)) = self.find_delegation(tr, &target, qtype, do_bit, elem) {
                    return (rrs, ns, extra, LookupResult::Delegation);
                }
                let out_of_tree =
                    elem.is_none() || qtype == RecordType::NS || (qtype == RecordType::SOA && target == self.origin);
                if out_of_tree {
                    let (lookup_rrs, result) = self.do_lookup(ctx, req, &target, qtype).await;
                    rrs.extend(lookup_rrs);
                    let auth = authority(data, do_bit, result);
                    let extra = self.additional_processing(data, &rrs, do_bit);
                    return (rrs, auth, extra, result);
                }
                let e = elem.unwrap();
                let cname = e.typ(RecordType::CNAME);
                if cname.is_empty() {
                    break;
                }
                if cname_target(&cname[0]).is_some_and(|t| *t == cname[0].name) {
                    return fail();
                }
                rrs.extend(cname.iter().cloned());
                if do_bit {
                    rrs.extend(sub_type_signature(e.typ(RecordType::RRSIG), RecordType::CNAME));
                }
                target = cname_target(&cname[0]).cloned().unwrap();
                elem = tr.search(&target);
                hops += 1;
                if hops > 8 {
                    let extra = self.additional_processing(data, &rrs, do_bit);
                    return (rrs, data.apex.ns(do_bit), extra, LookupResult::Success);
                }
            }

            let e = elem.unwrap();
            let targets = e.typ(qtype);
            if !targets.is_empty() {
                rrs.extend(targets.iter().cloned());
                if do_bit {
                    rrs.extend(sub_type_signature(e.typ(RecordType::RRSIG), qtype));
                }
            }
            let extra = self.additional_processing(data, &rrs, do_bit);
            (rrs, data.apex.ns(do_bit), extra, LookupResult::Success)
        })
    }

    /// `findDelegation`: a zone cut on the way down to `qname`.
    fn find_delegation(
        &self,
        tr: &Tree,
        qname: &Name,
        qtype: RecordType,
        do_bit: bool,
        exact: Option<&Elem>,
    ) -> Option<(Vec<Record>, Vec<Record>)> {
        let mut i = 1;
        loop {
            let (name, shot) = self.name_from_right(qname, i);
            if shot {
                return None;
            }
            if name == *qname {
                return exact.and_then(|e| delegation_from_elem(tr, e, qname, qtype, do_bit));
            }
            if let Some(e) = tr.search(&name)
                && let Some(d) = delegation_from_elem(tr, e, qname, qtype, do_bit)
            {
                return Some(d);
            }
            i += 1;
        }
    }

    /// `doLookup`: resolve an out-of-zone name through the server.
    async fn do_lookup(
        &self,
        ctx: &Context,
        req: &Request,
        target: &Name,
        qtype: RecordType,
    ) -> (Vec<Record>, LookupResult) {
        match upstream::lookup(ctx, req, target, qtype).await {
            Err(_) => (Vec::new(), LookupResult::ServerFailure),
            Ok(None) => (Vec::new(), LookupResult::Success),
            Ok(Some(m)) => {
                let rc = m.metadata.response_code;
                let answers = m.answers;
                let result = match rc {
                    ResponseCode::NXDomain => LookupResult::NameError,
                    ResponseCode::ServFail => LookupResult::ServerFailure,
                    ResponseCode::NoError if answers.is_empty() => LookupResult::NoData,
                    _ => LookupResult::Success,
                };
                (answers, result)
            }
        }
    }

    /// `additionalProcessing`: in-zone addresses of SRV, MX, SVCB and HTTPS targets.
    fn additional_processing(&self, data: &ZoneData, answer: &[Record], do_bit: bool) -> Vec<Record> {
        let mut extra = Vec::new();
        let mut seen: HashSet<Name> = HashSet::new();
        for rr in answer {
            let name = match &rr.data {
                RData::SRV(s) => &s.target,
                RData::MX(m) => &m.exchange,
                RData::SVCB(s) => &s.target_name,
                RData::HTTPS(h) => &h.0.target_name,
                _ => continue,
            };
            if name.is_root() || !self.origin.zone_of(name) {
                continue;
            }
            let key = name.to_lowercase();
            if !seen.insert(key) {
                continue;
            }
            let Some(e) = data.tree.search(name) else { continue };
            let sigs = e.typ(RecordType::RRSIG);
            for t in [RecordType::A, RecordType::AAAA] {
                let a = e.typ(t);
                if !a.is_empty() {
                    extra.extend(a.iter().cloned());
                    if do_bit {
                        extra.extend(sub_type_signature(sigs, t));
                    }
                }
            }
        }
        extra
    }
}

/// `delegationFromElem`: the NS set (and glue) of a zone cut at `elem`.
/// A DS query for the cut itself is answered by the parent, so it isn't a
/// delegation.
fn delegation_from_elem(
    tr: &Tree,
    elem: &Elem,
    qname: &Name,
    qtype: RecordType,
    do_bit: bool,
) -> Option<(Vec<Record>, Vec<Record>)> {
    if !elem.has(RecordType::NS) || (qtype == RecordType::DS && elem.name() == qname) {
        return None;
    }
    let mut ns = elem.typ(RecordType::NS).to_vec();
    let extra = tr.glue(&ns, do_bit);
    if do_bit {
        ns.extend(type_from_elem(elem, RecordType::DS, do_bit));
    }
    Some((ns, extra))
}

fn authority(data: &ZoneData, do_bit: bool, result: LookupResult) -> Vec<Record> {
    match result {
        LookupResult::NameError | LookupResult::NoData => data.apex.soa(do_bit),
        _ => data.apex.ns(do_bit),
    }
}

/// `ClosestEncloser`: the longest existing ancestor of `qname`.
fn closest_encloser<'a>(z: &Zone, tr: &'a Tree, qname: &Name) -> Option<&'a Elem> {
    let mut name = qname.clone();
    while !name.is_root() {
        if let Some(e) = tr.search(&name) {
            return Some(e);
        }
        name = name.base_name();
    }
    tr.search(&z.origin)
}
