//! Secondary zones: transferring a zone in from its primaries, checking
//! their SOA serial, the refresh/retry/expire loop and NOTIFY handling. A
//! port of `plugin/file/secondary.go` and `plugin/file/notify.go`.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kerndns_core::proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use kerndns_core::proto::rr::{RData, RecordType};
use kerndns_core::random::{rand_below, rand_id};
use kerndns_core::{Request, proto::rr::Record};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::zone::{Zone, ZoneData};

/// Sees every zone version transferred in, before it goes live
/// (`TransferInWithRecords`' validate function).
pub trait XfrHook: Send + Sync {
    /// Reject the transfer with `Err`; `Ok` returns what to run once the
    /// new data is live.
    fn check(&self, records: &[Record]) -> Result<Box<dyn FnOnce() + Send>, String>;
}

/// RFC 1982 serial arithmetic limit.
const MAX_SERIAL_INCREMENT: u32 = 2147483647;
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// `a < b` in serial number arithmetic, like `less`.
pub fn serial_less(a: u32, b: u32) -> bool {
    if a < b {
        b - a <= MAX_SERIAL_INCREMENT
    } else {
        a - b > MAX_SERIAL_INCREMENT
    }
}

async fn send(s: &mut TcpStream, m: &Message) -> Result<(), String> {
    let wire = m.to_vec().map_err(|e| e.to_string())?;
    let mut out = (wire.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(&wire);
    s.write_all(&out).await.map_err(|e| e.to_string())
}

async fn recv(s: &mut TcpStream) -> Result<Message, String> {
    let mut len = [0u8; 2];
    tokio::time::timeout(IO_TIMEOUT, s.read_exact(&mut len))
        .await
        .map_err(|_| "i/o timeout".to_string())?
        .map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; u16::from_be_bytes(len) as usize];
    tokio::time::timeout(IO_TIMEOUT, s.read_exact(&mut buf))
        .await
        .map_err(|_| "i/o timeout".to_string())?
        .map_err(|e| e.to_string())?;
    Message::from_vec(&buf).map_err(|e| e.to_string())
}

async fn connect(addr: &str) -> Result<TcpStream, String> {
    let sa: SocketAddr = addr.parse().map_err(|e| format!("{addr}: {e}"))?;
    tokio::time::timeout(IO_TIMEOUT, TcpStream::connect(sa))
        .await
        .map_err(|_| "i/o timeout".to_string())?
        .map_err(|e| e.to_string())
}

fn query(origin: &kerndns_core::proto::rr::Name, t: RecordType) -> Message {
    let mut m = Message::new(rand_id(), MessageType::Query, OpCode::Query);
    m.add_query(Query::query(origin.clone(), t));
    m
}

/// AXFR from one primary: every record, ending at the second SOA.
async fn axfr(origin: &kerndns_core::proto::rr::Name, from: &str) -> Result<Vec<Record>, String> {
    let mut s = connect(from).await?;
    let q = query(origin, RecordType::AXFR);
    send(&mut s, &q).await?;
    let mut records: Vec<Record> = Vec::new();
    let mut soas = 0;
    loop {
        let m = recv(&mut s).await?;
        if m.metadata.id != q.metadata.id {
            return Err("id mismatch".into());
        }
        if m.metadata.response_code != ResponseCode::NoError {
            return Err(format!("bad xfr rcode: {}", m.metadata.response_code));
        }
        for rr in m.answers {
            if records.is_empty() && rr.record_type() != RecordType::SOA {
                return Err("first record is not an SOA".into());
            }
            if rr.record_type() == RecordType::SOA {
                soas += 1;
            }
            records.push(rr);
            if soas == 2 {
                return Ok(records);
            }
        }
    }
}

impl Zone {
    /// `TransferIn`: AXFR from the first primary that works; then notify
    /// our own secondaries.
    pub async fn transfer_in(&self) -> Result<(), String> {
        if self.transfer_from.is_empty() {
            return Ok(());
        }
        let mut err = String::new();
        for from in &self.transfer_from {
            let records = match axfr(&self.origin, from).await {
                Ok(r) => r,
                Err(e) => {
                    kerndns_core::error!(
                        plugin = "file",
                        "Failed to transfer `{}' from {from:?}: {e}",
                        self.origin
                    );
                    err = e;
                    continue;
                }
            };
            let mut data = ZoneData::default();
            let mut bad = None;
            for rr in &records {
                if let Err(e) = data.insert(&self.origin, rr.clone()) {
                    bad = Some(e);
                    break;
                }
            }
            if let Some(e) = bad {
                kerndns_core::error!(
                    plugin = "file",
                    "Failed to parse transfer `{}' from: {from:?}: {e}",
                    self.origin
                );
                err = e;
                continue;
            }
            // like CoreDNS, a rejected version fails the whole transfer
            let after = match &self.xfr_hook {
                Some(h) => Some(h.check(&records)?),
                None => None,
            };
            self.set_data(data);
            kerndns_core::info!(plugin = "file", "Transferred: {} from {from}", self.origin);
            if let Some(r) = &self.registry {
                r.notify(&self.origin.to_string());
            }
            if let Some(after) = after {
                after();
            }
            return Ok(());
        }
        Err(err)
    }

    /// `shouldTransfer`: is a primary's SOA serial newer than ours?
    pub async fn should_transfer(&self) -> Result<bool, String> {
        let mut serial = None;
        let mut err = String::new();
        for from in &self.transfer_from {
            let res = async {
                let mut s = connect(from).await?;
                send(&mut s, &query(&self.origin, RecordType::SOA)).await?;
                recv(&mut s).await
            }
            .await;
            match res {
                Ok(m) if m.metadata.response_code == ResponseCode::NoError => {
                    if let Some(RData::SOA(soa)) = m
                        .answers
                        .iter()
                        .find(|r| r.record_type() == RecordType::SOA)
                        .map(|r| &r.data)
                    {
                        serial = Some(soa.serial);
                        break;
                    }
                }
                Ok(_) => {}
                Err(e) => err = e,
            }
        }
        let Some(serial) = serial else {
            return if err.is_empty() { Ok(false) } else { Err(err) };
        };
        Ok(match self.snapshot().apex.serial() {
            None => true,
            Some(ours) => serial_less(ours, serial),
        })
    }

    /// `isNotify`: a NOTIFY from one of our primaries.
    pub fn is_notify(&self, req: &Request) -> bool {
        req.msg.metadata.op_code == OpCode::Notify
            && self.transfer_from.iter().any(|f| {
                f.parse::<SocketAddr>()
                    .is_ok_and(|sa| sa.ip().to_canonical() == req.ip())
            })
    }

    /// Initial transfer with backoff (250ms doubling to 10s), then follow
    /// the SOA timers, like `transferAndUpdate` + `UpdateWithTransfer`.
    pub async fn transfer_and_update(self: Arc<Self>) {
        let mut dur = Duration::from_millis(250);
        while let Err(e) = self.transfer_in().await {
            kerndns_core::warning!(
                plugin = "secondary",
                "All '{}' masters failed to transfer, retrying in {}: {e}",
                self.origin,
                kerndns_core::duration::format_duration(dur)
            );
            tokio::time::sleep(dur).await;
            dur = (dur * 2).min(Duration::from_secs(10));
        }
        self.update().await;
    }

    async fn update(&self) {
        while self.snapshot().apex.soa.is_none() {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        let jitter = |max_ms: usize| Duration::from_millis(rand_below(max_ms) as u64);
        let mut retry_active = false;
        loop {
            let (refresh, retry, expire) = match self.snapshot().apex.soa.as_ref().map(|r| &r.data) {
                Some(RData::SOA(s)) => (s.refresh.max(1), s.retry.max(1), s.expire.max(1)),
                _ => (3600, 600, 86400),
            };
            let secs = |s: i32| Duration::from_secs(s as u64);
            let now = tokio::time::Instant::now();
            let mut refresh_t = tokio::time::interval_at(now + secs(refresh), secs(refresh));
            let mut retry_t = tokio::time::interval_at(now + secs(retry), secs(retry));
            let mut expire_t = tokio::time::interval_at(now + secs(expire), secs(expire));
            // restart the timers after a successful check
            loop {
                tokio::select! {
                    _ = expire_t.tick() => {
                        if retry_active {
                            self.expired.store(true, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                    _ = retry_t.tick() => {
                        if !retry_active {
                            continue;
                        }
                        tokio::time::sleep(jitter(2000)).await;
                        match self.should_transfer().await {
                            Err(e) => kerndns_core::warning!(plugin = "file", "Failed retry check {e}"),
                            Ok(ok) => {
                                if ok && self.transfer_in().await.is_err() {
                                    continue;
                                }
                                retry_active = false;
                                break;
                            }
                        }
                    }
                    _ = refresh_t.tick() => {
                        tokio::time::sleep(jitter(5000)).await;
                        match self.should_transfer().await {
                            Err(e) => {
                                kerndns_core::warning!(plugin = "file", "Failed refresh check {e}");
                                retry_active = true;
                            }
                            Ok(ok) => {
                                if ok && self.transfer_in().await.is_err() {
                                    retry_active = true;
                                    continue;
                                }
                                retry_active = false;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serials() {
        assert!(serial_less(1, 2));
        assert!(!serial_less(2, 1));
        assert!(serial_less(u32::MAX, 1), "wraps around");
        assert!(!serial_less(5, 5));
    }
}
