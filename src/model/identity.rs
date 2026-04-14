use rand::Rng;
use serde_json::Value;
use std::collections::HashMap;

use super::account::{CanonicalEnvData, CanonicalProcessData, CanonicalPromptEnvData};

fn env_presets() -> Vec<CanonicalEnvData> {
    vec![
        // --- darwin arm64 ---
        CanonicalEnvData {
            platform: "darwin".into(),
            platform_raw: "darwin".into(),
            arch: "arm64".into(),
            node_version: "v22.15.0".into(),
            terminal: "iTerm.app".into(),
            package_managers: "npm,pnpm".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-darwin".into(),
            vcs: "git".into(),
            ..Default::default()
        },
        CanonicalEnvData {
            platform: "darwin".into(),
            platform_raw: "darwin".into(),
            arch: "arm64".into(),
            node_version: "v24.3.0".into(),
            terminal: "Apple_Terminal".into(),
            package_managers: "npm,yarn".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-darwin".into(),
            vcs: "git".into(),
            ..Default::default()
        },
        CanonicalEnvData {
            platform: "darwin".into(),
            platform_raw: "darwin".into(),
            arch: "arm64".into(),
            node_version: "v22.15.0".into(),
            terminal: "vscode".into(),
            package_managers: "npm,pnpm".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-darwin".into(),
            vcs: "git".into(),
            ..Default::default()
        },
        CanonicalEnvData {
            platform: "darwin".into(),
            platform_raw: "darwin".into(),
            arch: "arm64".into(),
            node_version: "v24.3.0".into(),
            terminal: "WarpTerminal".into(),
            package_managers: "npm".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-darwin".into(),
            vcs: "git".into(),
            ..Default::default()
        },
        // --- darwin x64 ---
        CanonicalEnvData {
            platform: "darwin".into(),
            platform_raw: "darwin".into(),
            arch: "x64".into(),
            node_version: "v22.15.0".into(),
            terminal: "iTerm.app".into(),
            package_managers: "npm,yarn".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-darwin".into(),
            vcs: "git".into(),
            ..Default::default()
        },
        CanonicalEnvData {
            platform: "darwin".into(),
            platform_raw: "darwin".into(),
            arch: "x64".into(),
            node_version: "v24.3.0".into(),
            terminal: "Apple_Terminal".into(),
            package_managers: "npm,pnpm".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-darwin".into(),
            vcs: "git".into(),
            ..Default::default()
        },
        // --- linux ---
        CanonicalEnvData {
            platform: "linux".into(),
            platform_raw: "linux".into(),
            arch: "x64".into(),
            node_version: "v22.15.0".into(),
            terminal: "gnome-terminal".into(),
            package_managers: "npm,pnpm".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-linux".into(),
            vcs: "git".into(),
            ..Default::default()
        },
        CanonicalEnvData {
            platform: "linux".into(),
            platform_raw: "linux".into(),
            arch: "x64".into(),
            node_version: "v24.3.0".into(),
            terminal: "ssh-session".into(),
            package_managers: "npm".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-linux".into(),
            vcs: "git".into(),
            ..Default::default()
        },
        CanonicalEnvData {
            platform: "linux".into(),
            platform_raw: "linux".into(),
            arch: "x64".into(),
            node_version: "v22.15.0".into(),
            terminal: "xterm-256color".into(),
            package_managers: "npm,yarn".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-linux".into(),
            vcs: "git".into(),
            ..Default::default()
        },
        // --- win32 ---
        CanonicalEnvData {
            platform: "win32".into(),
            platform_raw: "win32".into(),
            arch: "x64".into(),
            node_version: "v22.15.0".into(),
            terminal: "windows-terminal".into(),
            package_managers: "npm,pnpm".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-win32".into(),
            vcs: "git".into(),
            ..Default::default()
        },
        CanonicalEnvData {
            platform: "win32".into(),
            platform_raw: "win32".into(),
            arch: "x64".into(),
            node_version: "v24.3.0".into(),
            terminal: "vscode".into(),
            package_managers: "npm,yarn".into(),
            runtimes: "node".into(),
            is_claude_ai_auth: true,
            version: "2.1.81".into(),
            version_base: "2.1.81".into(),
            build_time: "2026-03-20T21:26:18Z".into(),
            deployment_environment: "unknown-win32".into(),
            vcs: "git".into(),
            ..Default::default()
        },
    ]
}

fn prompt_presets() -> HashMap<&'static str, CanonicalPromptEnvData> {
    let mut m = HashMap::new();
    m.insert(
        "darwin",
        CanonicalPromptEnvData {
            platform: "darwin".into(),
            shell: "zsh".into(),
            os_version: "Darwin 24.4.0".into(),
            working_dir: "/Users/user/projects".into(),
        },
    );
    m.insert(
        "linux",
        CanonicalPromptEnvData {
            platform: "linux".into(),
            shell: "bash".into(),
            os_version: "Linux 6.5.0-generic".into(),
            working_dir: "/home/user/projects".into(),
        },
    );
    m.insert(
        "win32",
        CanonicalPromptEnvData {
            platform: "win32".into(),
            shell: "bash (use Unix shell syntax, not Windows \u{2014} e.g., /dev/null not NUL, forward slashes in paths)".into(),
            os_version: "Windows 10 Pro 10.0.19045".into(),
            working_dir: "/c/Users/user/projects".into(),
        },
    );
    m
}

static MEMORY_PRESETS: &[i64] = &[
    0, // process.constrainedMemory() returns 0 on non-containerized environments
];

/// 生成随机的 64 字符十六进制字符串。
pub fn generate_device_id() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// 为新账号生成全部规范化身份字段。
pub fn generate_canonical_identity() -> (String, Value, Value, Value) {
    let device_id = generate_device_id();
    let mut rng = rand::thread_rng();

    let presets = env_presets();
    let preset = &presets[rng.gen_range(0..presets.len())];
    let env_json = serde_json::to_value(preset).expect("env preset serialize");

    let prompts = prompt_presets();
    let prompt_env = prompts
        .get(preset.platform.as_str())
        .expect("prompt preset");
    let prompt_json = serde_json::to_value(prompt_env).expect("prompt preset serialize");

    let mem = MEMORY_PRESETS[rng.gen_range(0..MEMORY_PRESETS.len())];
    let process = CanonicalProcessData {
        constrained_memory: mem,
        rss_range: [300_000_000, 500_000_000],
        heap_total_range: [40_000_000, 80_000_000],
        heap_used_range: [100_000_000, 200_000_000],
        external_range: [1_000_000, 3_000_000],
        array_buffers_range: [10_000, 50_000],
    };
    let process_json = serde_json::to_value(&process).expect("process serialize");

    (device_id, env_json, prompt_json, process_json)
}

/// 构造 proto schema 完整的 env JSON（含所有 ~30 个字段）。
/// 供 rewriter 和 telemetry 共用，避免重复定义。
pub fn build_full_env_json(env: &CanonicalEnvData) -> Value {
    serde_json::json!({
        "platform": env.platform,
        "platform_raw": env.platform_raw,
        "arch": env.arch,
        "node_version": env.node_version,
        "terminal": env.terminal,
        "package_managers": env.package_managers,
        "runtimes": env.runtimes,
        "is_running_with_bun": false,
        "is_ci": false,
        "is_claubbit": false,
        "is_claude_code_remote": false,
        "is_local_agent_mode": false,
        "is_conductor": false,
        "is_github_action": false,
        "is_claude_code_action": false,
        "is_claude_ai_auth": env.is_claude_ai_auth,
        "version": env.version,
        "version_base": env.version_base,
        "build_time": env.build_time,
        "deployment_environment": env.deployment_environment,
        "vcs": env.vcs,
        "github_event_name": "",
        "github_actions_runner_environment": "",
        "github_actions_runner_os": "",
        "github_action_ref": "",
        "wsl_version": "",
        "remote_environment_type": "",
        "claude_code_container_id": "",
        "claude_code_remote_session_id": "",
        "tags": [],
        "coworker_type": "",
        "linux_distro_id": "",
        "linux_distro_version": "",
        "linux_kernel": "",
    })
}
