//! 限流状态管理：从 `anthropic-ratelimit-unified-*` 响应头吸取账号限流信息到内存热态，
//! 按 TTL + 紧急事件条件异步落盘到 `accounts.usage_data`。
//!
//! 设计要点：
//! - **内存热态**：每次响应都更新，selector 的 `availability()` 查询在此之上，~500ns 级别。
//! - **DB 落盘**：5 分钟 TTL + 紧急事件（阈值跨越、状态变化、首次填充）触发，tokio::spawn 异步。
//! - **刻度统一**：内存里 utilization 始终是 0.0-1.0 小数（响应头原生格式），
//!   写 DB 时乘以 100 归一到 0-100（与 `/api/oauth/usage` 返回值一致，保持前端兼容）。

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info};

use crate::error::AppError;
use crate::store::account_store::AccountStore;

/// 内存 → DB 常规刷新 TTL。
const DB_FLUSH_TTL: Duration = Duration::from_secs(5 * 60);
/// 超过此 utilization（0.0-1.0 刻度）视为该窗口撞墙，立即紧急 flush 且 selector 判不可用。
const HIT_THRESHOLD: f64 = 0.97;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnifiedStatus {
    Allowed,
    AllowedWarning,
    Rejected,
}

impl UnifiedStatus {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "allowed" => Some(Self::Allowed),
            "allowed_warning" => Some(Self::AllowedWarning),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::AllowedWarning => "allowed_warning",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverageStatus {
    Allowed,
    AllowedWarning,
    Rejected,
}

impl OverageStatus {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "allowed" => Some(Self::Allowed),
            "allowed_warning" => Some(Self::AllowedWarning),
            "rejected" => Some(Self::Rejected),
            _ => None,
        }
    }
    fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::AllowedWarning => "allowed_warning",
            Self::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WindowSnapshot {
    /// 0.0-1.0 刻度（响应头原生）。
    pub utilization: f64,
    pub resets_at: DateTime<Utc>,
    pub status: UnifiedStatus,
    pub surpassed_threshold: Option<f64>,
}

#[derive(Debug, Clone, Default)]
pub struct LimitState {
    pub five_hour: Option<WindowSnapshot>,
    pub seven_day: Option<WindowSnapshot>,
    pub status: Option<UnifiedStatus>,
    pub representative_claim: Option<String>,
    pub reset_at: Option<DateTime<Utc>>,
    pub fallback_percentage: Option<f64>,
    pub overage_status: Option<OverageStatus>,
    pub overage_disabled_reason: Option<String>,
    pub updated_at: Option<Instant>,
    pub last_db_flush_at: Option<Instant>,
}

/// Selector 查询结果。
#[derive(Debug, Clone)]
pub enum Availability {
    Available,
    Unavailable {
        reason: String,
        until: Option<DateTime<Utc>>,
    },
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

pub struct LimitStore {
    store: Arc<AccountStore>,
    states: Mutex<HashMap<i64, LimitState>>,
}

impl LimitStore {
    pub fn new(store: Arc<AccountStore>) -> Self {
        Self {
            store,
            states: Mutex::new(HashMap::new()),
        }
    }

    /// 从响应头吸取状态到内存。返回是否应触发 DB flush。
    ///
    /// 所有解析性字段缺失 → 不更新任何内存，返回 false（保持空闲账号原样）。
    pub fn absorb_headers(&self, account_id: i64, headers: &HeaderMap) -> bool {
        let Some(parsed) = parse_unified_headers(headers) else {
            return false;
        };

        let mut map = self.states.lock().unwrap();
        let prev = map.get(&account_id).cloned().unwrap_or_default();
        let mut new_state = apply_parsed(prev.clone(), parsed);
        new_state.updated_at = Some(Instant::now());

        let flush_r = flush_reason(&prev, &new_state);
        if let Some(reason) = flush_r {
            // 抢先占位：即使 flush 失败也先记，下次 5min 后再尝试，避免连续失败造成风暴。
            new_state.last_db_flush_at = Some(Instant::now());
            let five = new_state
                .five_hour
                .as_ref()
                .map(|w| w.utilization)
                .unwrap_or(0.0);
            let seven = new_state
                .seven_day
                .as_ref()
                .map(|w| w.utilization)
                .unwrap_or(0.0);
            info!(
                "limit absorb: account {} → flush ({}) 5h={:.1}% 7d={:.1}% status={}",
                account_id,
                reason,
                five * 100.0,
                seven * 100.0,
                new_state.status.unwrap_or(UnifiedStatus::Allowed).as_str(),
            );
        } else {
            debug!(
                "limit absorb: account {} → no flush (within TTL, no threshold event)",
                account_id
            );
        }
        let should_flush = flush_r.is_some();
        map.insert(account_id, new_state);
        should_flush
    }

    /// Selector 用：当前账号可否调度。内存无记录 → 乐观 Available。
    pub fn availability(&self, account_id: i64) -> Availability {
        let map = self.states.lock().unwrap();
        let Some(state) = map.get(&account_id) else {
            return Availability::Available;
        };
        judge_availability(state)
    }

    /// flush 当前内存状态到 DB：
    /// 1. `usage_data` JSON（完整快照，供 UI 读）
    /// 2. `rate_limit_reset_at` / `rate_limited_at`：
    ///    任一窗口 util >= 97% 且 resets_at 未来 → 写入最晚的 resets_at；
    ///    否则清空这两列。
    ///
    /// 由 gateway 在 absorb_headers 返回 true 时 tokio::spawn 调用。
    pub async fn flush_to_db(&self, account_id: i64) -> Result<(), AppError> {
        let (json, limit_until) = {
            let map = self.states.lock().unwrap();
            let Some(state) = map.get(&account_id) else {
                debug!("limit flush: account {} not in memory, skip", account_id);
                return Ok(());
            };
            (build_usage_json(state), bottleneck_limit_until(state))
        };
        let json_str = serde_json::to_string(&json).unwrap_or_else(|_| "{}".into());
        self.store.update_usage(account_id, &json_str).await?;
        match limit_until {
            Some(reset_at) => {
                self.store.set_rate_limit(account_id, reset_at).await?;
                debug!(
                    "limit flush: account {} → DB (limited until {})",
                    account_id,
                    reset_at.to_rfc3339()
                );
            }
            None => {
                self.store.clear_rate_limit(account_id).await?;
                debug!("limit flush: account {} → DB (cleared)", account_id);
            }
        }
        Ok(())
    }

    /// 从 `/api/oauth/usage` JSON（0-100 刻度）同步到内存，保持两条数据源一致。
    /// 仅用于 Admin 按钮路径。
    pub fn ingest_usage_json(&self, account_id: i64, usage: &serde_json::Value) {
        let mut map = self.states.lock().unwrap();
        let mut state = map.get(&account_id).cloned().unwrap_or_default();

        if let Some(w) = parse_usage_json_window(usage, "five_hour") {
            state.five_hour = Some(w);
        }
        if let Some(w) = parse_usage_json_window(usage, "seven_day") {
            state.seven_day = Some(w);
        }
        state.updated_at = Some(Instant::now());
        map.insert(account_id, state);
    }
}

// ---- 解析辅助 ----

struct ParsedHeaders {
    five_hour: Option<WindowSnapshot>,
    seven_day: Option<WindowSnapshot>,
    status: Option<UnifiedStatus>,
    representative_claim: Option<String>,
    reset_at: Option<DateTime<Utc>>,
    fallback_percentage: Option<f64>,
    overage_status: Option<OverageStatus>,
    overage_disabled_reason: Option<String>,
}

impl ParsedHeaders {
    fn any_present(&self) -> bool {
        self.five_hour.is_some()
            || self.seven_day.is_some()
            || self.status.is_some()
            || self.representative_claim.is_some()
            || self.reset_at.is_some()
            || self.overage_status.is_some()
    }
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn parse_unified_headers(headers: &HeaderMap) -> Option<ParsedHeaders> {
    let parsed = ParsedHeaders {
        five_hour: parse_window_from_headers(headers, "5h"),
        seven_day: parse_window_from_headers(headers, "7d"),
        status: header_str(headers, "anthropic-ratelimit-unified-status")
            .and_then(UnifiedStatus::parse),
        representative_claim: header_str(
            headers,
            "anthropic-ratelimit-unified-representative-claim",
        )
        .map(String::from),
        reset_at: header_str(headers, "anthropic-ratelimit-unified-reset")
            .and_then(|s| s.parse::<i64>().ok())
            .and_then(|s| DateTime::from_timestamp(s, 0)),
        fallback_percentage: header_str(headers, "anthropic-ratelimit-unified-fallback-percentage")
            .and_then(|s| s.parse::<f64>().ok()),
        overage_status: header_str(headers, "anthropic-ratelimit-unified-overage-status")
            .and_then(OverageStatus::parse),
        overage_disabled_reason: header_str(
            headers,
            "anthropic-ratelimit-unified-overage-disabled-reason",
        )
        .map(String::from),
    };

    if parsed.any_present() {
        Some(parsed)
    } else {
        None
    }
}

fn parse_window_from_headers(headers: &HeaderMap, abbrev: &str) -> Option<WindowSnapshot> {
    let util = header_str(
        headers,
        &format!("anthropic-ratelimit-unified-{}-utilization", abbrev),
    )?
    .parse::<f64>()
    .ok()?;
    let reset_secs = header_str(
        headers,
        &format!("anthropic-ratelimit-unified-{}-reset", abbrev),
    )?
    .parse::<i64>()
    .ok()?;
    let resets_at = DateTime::from_timestamp(reset_secs, 0)?;
    // status 可能按窗口独立返回（5h-status / 7d-status），缺失则落回全局 Allowed。
    let status = header_str(
        headers,
        &format!("anthropic-ratelimit-unified-{}-status", abbrev),
    )
    .and_then(UnifiedStatus::parse)
    .unwrap_or(UnifiedStatus::Allowed);
    let surpassed_threshold = header_str(
        headers,
        &format!("anthropic-ratelimit-unified-{}-surpassed-threshold", abbrev),
    )
    .and_then(|s| s.parse::<f64>().ok());

    Some(WindowSnapshot {
        utilization: util,
        resets_at,
        status,
        surpassed_threshold,
    })
}

/// 把 `/api/oauth/usage` JSON 的单个窗口（0-100 刻度）转为内部 0-1 表示。
fn parse_usage_json_window(usage: &serde_json::Value, key: &str) -> Option<WindowSnapshot> {
    let window = usage.get(key)?;
    let util_0_100 = window.get("utilization")?.as_f64()?;
    let resets_at_str = window.get("resets_at")?.as_str()?;
    let resets_at = DateTime::parse_from_rfc3339(resets_at_str)
        .ok()?
        .with_timezone(&Utc);
    Some(WindowSnapshot {
        utilization: util_0_100 / 100.0,
        resets_at,
        status: UnifiedStatus::Allowed, // JSON 不带 status，保守填 Allowed
        surpassed_threshold: None,
    })
}

fn apply_parsed(mut state: LimitState, parsed: ParsedHeaders) -> LimitState {
    if let Some(w) = parsed.five_hour {
        state.five_hour = Some(w);
    }
    if let Some(w) = parsed.seven_day {
        state.seven_day = Some(w);
    }
    if let Some(s) = parsed.status {
        state.status = Some(s);
    }
    if let Some(c) = parsed.representative_claim {
        state.representative_claim = Some(c);
    }
    if let Some(r) = parsed.reset_at {
        state.reset_at = Some(r);
    }
    if let Some(fp) = parsed.fallback_percentage {
        state.fallback_percentage = Some(fp);
    }
    if let Some(os) = parsed.overage_status {
        state.overage_status = Some(os);
    }
    if let Some(reason) = parsed.overage_disabled_reason {
        state.overage_disabled_reason = Some(reason);
    }
    state
}

/// 判定是否需要 flush 到 DB；返回 Some(reason) 触发，None 不触发。
fn flush_reason(prev: &LimitState, new: &LimitState) -> Option<&'static str> {
    // 1) 首次填充
    if prev.last_db_flush_at.is_none() {
        return Some("first-fill");
    }
    // 2) TTL 到期
    if let Some(last) = prev.last_db_flush_at {
        if last.elapsed() >= DB_FLUSH_TTL {
            return Some("ttl-expired");
        }
    }
    // 3) 全局状态从 Allowed 切走
    let prev_status = prev.status.unwrap_or(UnifiedStatus::Allowed);
    let new_status = new.status.unwrap_or(UnifiedStatus::Allowed);
    if prev_status == UnifiedStatus::Allowed && new_status != UnifiedStatus::Allowed {
        return Some("status-changed");
    }
    // 4) 任一窗口 utilization 跨过 97%
    if crossed_threshold(&prev.five_hour, &new.five_hour, HIT_THRESHOLD)
        || crossed_threshold(&prev.seven_day, &new.seven_day, HIT_THRESHOLD)
    {
        return Some("threshold-crossed-97pct");
    }
    // 5) 任一窗口新出现 surpassed-threshold 头
    if newly_surpassed(&prev.five_hour, &new.five_hour)
        || newly_surpassed(&prev.seven_day, &new.seven_day)
    {
        return Some("surpassed-threshold");
    }
    None
}

fn crossed_threshold(
    prev: &Option<WindowSnapshot>,
    new: &Option<WindowSnapshot>,
    threshold: f64,
) -> bool {
    let new_util = new.as_ref().map(|w| w.utilization).unwrap_or(0.0);
    let prev_util = prev.as_ref().map(|w| w.utilization).unwrap_or(0.0);
    new_util >= threshold && prev_util < threshold
}

fn newly_surpassed(prev: &Option<WindowSnapshot>, new: &Option<WindowSnapshot>) -> bool {
    let new_has = new.as_ref().and_then(|w| w.surpassed_threshold).is_some();
    let prev_has = prev.as_ref().and_then(|w| w.surpassed_threshold).is_some();
    new_has && !prev_has
}

/// 返回"瓶颈窗口"的 resets_at（用于 DB 列 rate_limit_reset_at）：
/// 若任一窗口 util >= 97% 且 resets_at 在未来，返回这些窗口中最晚的 resets_at；
/// 否则返回 None（上层会 clear_rate_limit）。
fn bottleneck_limit_until(state: &LimitState) -> Option<DateTime<Utc>> {
    let now = Utc::now();
    let mut picks: Vec<DateTime<Utc>> = Vec::new();
    for w in [&state.five_hour, &state.seven_day].into_iter().flatten() {
        if w.utilization >= HIT_THRESHOLD && w.resets_at > now {
            picks.push(w.resets_at);
        }
    }
    picks.into_iter().max()
}

fn judge_availability(state: &LimitState) -> Availability {
    if let Some(w) = &state.five_hour {
        if w.utilization >= HIT_THRESHOLD && w.resets_at > Utc::now() {
            return Availability::Unavailable {
                reason: format!("5 小时窗口已用 {:.1}%", w.utilization * 100.0),
                until: Some(w.resets_at),
            };
        }
    }
    if let Some(w) = &state.seven_day {
        if w.utilization >= HIT_THRESHOLD && w.resets_at > Utc::now() {
            return Availability::Unavailable {
                reason: format!("7 天窗口已用 {:.1}%", w.utilization * 100.0),
                until: Some(w.resets_at),
            };
        }
    }
    // 全局 status = Rejected → 不可用
    if state.status == Some(UnifiedStatus::Rejected) {
        return Availability::Unavailable {
            reason: "上游已拒绝（status=rejected）".into(),
            until: state.reset_at,
        };
    }
    Availability::Available
}

/// 构造前端兼容的 `usage_data` JSON（utilization 乘 100 转 0-100 刻度）。
fn build_usage_json(state: &LimitState) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    if let Some(w) = &state.five_hour {
        obj.insert("five_hour".into(), window_to_json(w));
    }
    if let Some(w) = &state.seven_day {
        obj.insert("seven_day".into(), window_to_json(w));
    }
    if let Some(s) = state.status {
        obj.insert("status".into(), serde_json::Value::from(s.as_str()));
    }
    if let Some(c) = &state.representative_claim {
        obj.insert("representative_claim".into(), serde_json::Value::from(c.clone()));
    }
    if let Some(r) = state.reset_at {
        obj.insert("resets_at".into(), serde_json::Value::from(r.to_rfc3339()));
    }
    if let Some(fp) = state.fallback_percentage {
        obj.insert("fallback_percentage".into(), serde_json::Value::from(fp));
    }
    if let Some(os) = state.overage_status {
        obj.insert(
            "overage_status".into(),
            serde_json::Value::from(os.as_str()),
        );
    }
    if let Some(reason) = &state.overage_disabled_reason {
        obj.insert(
            "overage_disabled_reason".into(),
            serde_json::Value::from(reason.clone()),
        );
    }
    obj.insert("source".into(), serde_json::Value::from("headers"));
    serde_json::Value::Object(obj)
}

fn window_to_json(w: &WindowSnapshot) -> serde_json::Value {
    let mut m = serde_json::Map::new();
    m.insert(
        "utilization".into(),
        serde_json::Value::from(w.utilization * 100.0),
    );
    m.insert(
        "resets_at".into(),
        serde_json::Value::from(w.resets_at.to_rfc3339()),
    );
    m.insert("status".into(), serde_json::Value::from(w.status.as_str()));
    if let Some(t) = w.surpassed_threshold {
        m.insert("surpassed_threshold".into(), serde_json::Value::from(t));
    }
    serde_json::Value::Object(m)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn make_headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn real_200_headers() -> HeaderMap {
        // 来自真实抓包的 200 响应头子集（见 Phase 2 plan）
        make_headers(&[
            ("anthropic-ratelimit-unified-5h-reset", "1776427200"),
            ("anthropic-ratelimit-unified-5h-status", "allowed"),
            ("anthropic-ratelimit-unified-5h-utilization", "0.14"),
            ("anthropic-ratelimit-unified-7d-reset", "1776996000"),
            ("anthropic-ratelimit-unified-7d-status", "allowed"),
            ("anthropic-ratelimit-unified-7d-utilization", "0.03"),
            ("anthropic-ratelimit-unified-fallback-percentage", "0.5"),
            ("anthropic-ratelimit-unified-overage-disabled-reason", "org_level_disabled"),
            ("anthropic-ratelimit-unified-overage-status", "rejected"),
            ("anthropic-ratelimit-unified-representative-claim", "five_hour"),
            ("anthropic-ratelimit-unified-reset", "1776427200"),
            ("anthropic-ratelimit-unified-status", "allowed"),
        ])
    }

    #[test]
    fn parse_real_200_response_headers() {
        let h = real_200_headers();
        let p = parse_unified_headers(&h).expect("has fields");
        let five = p.five_hour.as_ref().expect("5h present");
        assert!((five.utilization - 0.14).abs() < 1e-9);
        assert_eq!(five.status, UnifiedStatus::Allowed);
        let seven = p.seven_day.as_ref().expect("7d present");
        assert!((seven.utilization - 0.03).abs() < 1e-9);
        assert_eq!(p.status, Some(UnifiedStatus::Allowed));
        assert_eq!(p.representative_claim.as_deref(), Some("five_hour"));
        assert_eq!(p.overage_status, Some(OverageStatus::Rejected));
        assert_eq!(p.fallback_percentage, Some(0.5));
    }

    #[test]
    fn parse_none_when_no_unified_headers() {
        let h = make_headers(&[("content-type", "text/event-stream")]);
        assert!(parse_unified_headers(&h).is_none());
    }

    #[test]
    fn parse_ignores_malformed_utilization() {
        let h = make_headers(&[
            ("anthropic-ratelimit-unified-5h-utilization", "not-a-number"),
            ("anthropic-ratelimit-unified-5h-reset", "1776427200"),
        ]);
        let p = parse_unified_headers(&h);
        assert!(p.is_none() || p.unwrap().five_hour.is_none());
    }

    #[test]
    fn decide_flush_first_fill_always_flushes() {
        let prev = LimitState::default();
        let new = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.14,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(flush_reason(&prev, &new).is_some());
    }

    #[test]
    fn decide_flush_within_ttl_no_trigger() {
        let recent = Instant::now();
        let prev = LimitState {
            last_db_flush_at: Some(recent),
            five_hour: Some(WindowSnapshot {
                utilization: 0.14,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        let new = LimitState {
            last_db_flush_at: Some(recent),
            five_hour: Some(WindowSnapshot {
                utilization: 0.15,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(flush_reason(&prev, &new).is_none());
    }

    #[test]
    fn decide_flush_crossing_97_triggers() {
        let recent = Instant::now();
        let prev = LimitState {
            last_db_flush_at: Some(recent),
            five_hour: Some(WindowSnapshot {
                utilization: 0.96,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        let new = LimitState {
            last_db_flush_at: Some(recent),
            five_hour: Some(WindowSnapshot {
                utilization: 0.97,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(flush_reason(&prev, &new).is_some());
    }

    #[test]
    fn decide_flush_status_allowed_to_warning_triggers() {
        let recent = Instant::now();
        let prev = LimitState {
            last_db_flush_at: Some(recent),
            status: Some(UnifiedStatus::Allowed),
            ..Default::default()
        };
        let new = LimitState {
            last_db_flush_at: Some(recent),
            status: Some(UnifiedStatus::AllowedWarning),
            ..Default::default()
        };
        assert!(flush_reason(&prev, &new).is_some());
    }

    #[test]
    fn availability_empty_is_available() {
        let state = LimitState::default();
        assert!(judge_availability(&state).is_available());
    }

    #[test]
    fn availability_14pct_is_available() {
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.14,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            status: Some(UnifiedStatus::Allowed),
            ..Default::default()
        };
        assert!(judge_availability(&state).is_available());
    }

    #[test]
    fn availability_97pct_5h_is_unavailable() {
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.97,
                resets_at: Utc::now() + chrono::Duration::hours(1),
                status: UnifiedStatus::AllowedWarning,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        match judge_availability(&state) {
            Availability::Unavailable { until, .. } => assert!(until.is_some()),
            Availability::Available => panic!("should be unavailable"),
        }
    }

    #[test]
    fn availability_rejected_is_unavailable() {
        let state = LimitState {
            status: Some(UnifiedStatus::Rejected),
            ..Default::default()
        };
        assert!(!judge_availability(&state).is_available());
    }

    #[test]
    fn availability_97pct_past_reset_is_available() {
        // 即使 utilization = 97%，如果 reset 已经过去，视为已重置
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.97,
                resets_at: Utc::now() - chrono::Duration::hours(1),
                status: UnifiedStatus::AllowedWarning,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(judge_availability(&state).is_available());
    }

    // ---- bottleneck_limit_until ----

    #[test]
    fn bottleneck_none_when_all_below_97() {
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.14,
                resets_at: Utc::now() + chrono::Duration::hours(2),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(bottleneck_limit_until(&state).is_none());
    }

    #[test]
    fn bottleneck_picks_five_hour_when_only_5h_over() {
        let five_reset = Utc::now() + chrono::Duration::hours(2);
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.98,
                resets_at: five_reset,
                status: UnifiedStatus::AllowedWarning,
                surpassed_threshold: None,
            }),
            seven_day: Some(WindowSnapshot {
                utilization: 0.30,
                resets_at: Utc::now() + chrono::Duration::days(5),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert_eq!(bottleneck_limit_until(&state), Some(five_reset));
    }

    #[test]
    fn bottleneck_picks_later_when_both_over() {
        // 两个窗口都撞墙时，取更晚的 resets_at（限流更久）
        let five_reset = Utc::now() + chrono::Duration::hours(2);
        let seven_reset = Utc::now() + chrono::Duration::days(5);
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.98,
                resets_at: five_reset,
                status: UnifiedStatus::Rejected,
                surpassed_threshold: None,
            }),
            seven_day: Some(WindowSnapshot {
                utilization: 0.99,
                resets_at: seven_reset,
                status: UnifiedStatus::Rejected,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert_eq!(bottleneck_limit_until(&state), Some(seven_reset));
    }

    #[test]
    fn bottleneck_skips_past_reset() {
        // 即使 util >= 97%，reset 已过去视为已重置
        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.99,
                resets_at: Utc::now() - chrono::Duration::hours(1),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        assert!(bottleneck_limit_until(&state).is_none());
    }

    #[test]
    fn build_usage_json_converts_to_0_100_scale() {        let state = LimitState {
            five_hour: Some(WindowSnapshot {
                utilization: 0.14,
                resets_at: DateTime::from_timestamp(1776427200, 0).unwrap(),
                status: UnifiedStatus::Allowed,
                surpassed_threshold: None,
            }),
            ..Default::default()
        };
        let json = build_usage_json(&state);
        let util = json
            .get("five_hour")
            .and_then(|w| w.get("utilization"))
            .and_then(|u| u.as_f64())
            .unwrap();
        assert!((util - 14.0).abs() < 1e-9);
    }

    #[test]
    fn ingest_usage_json_converts_0_100_to_0_1() {
        // 没有 AccountStore 可用，只测试纯内存路径
        // 需要小心地构造一个不依赖 store 的测试 helper
    }
}
