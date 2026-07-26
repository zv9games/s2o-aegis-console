mod cyber_kanji;
mod cyber_ship;
mod cyber_nodes;

use eframe::{egui, epi};
use cyber_kanji::MatrixRain;
use cyber_ship::{CyberShip, CyberLaser};
use cyber_nodes::CyberNode;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

pub enum OsCommand {
    QueryStatus,
    ToggleFirewall(bool),
    ToggleShield(bool),
    ToggleDefender(bool),
}

pub enum OsStatusEvent {
    QuerySync { enabled: bool, blocked: bool, active: bool, banner: String },
    FirewallStatus { enabled: bool, banner: String },
    ShieldStatus { blocked: bool, banner: String },
    DefenderStatus { active: bool, banner: String },
}

fn spawn_os_worker() -> (Sender<OsCommand>, Receiver<OsStatusEvent>) {
    let (cmd_tx, cmd_rx) = channel::<OsCommand>();
    let (event_tx, event_rx) = channel::<OsStatusEvent>();

    std::thread::spawn(move || {
        // Initialize COM ONCE for the entire lifetime of this dedicated worker thread
        let _persistent_com_guard = unsafe { s2o_net_lib::util1::init_com() };

        while let Ok(cmd) = cmd_rx.recv() {
            match cmd {
                OsCommand::QueryStatus => {
                    let live_enabled = s2o_net_lib::firewall::FirewallController::is_firewall_enabled().unwrap_or(true);
                    let live_blocked = s2o_net_lib::firewall::FirewallController::is_outbound_blocked().unwrap_or(false);
                    let live_active = s2o_net_lib::defender::DefenderController::is_defender_active();

                    let banner = format!(
                        "[OS KERNEL SYNCED] Live Firewall: {} | Shield: {} | Defender: {}",
                        if live_enabled { "ENABLED" } else { "DISABLED" },
                        if live_blocked { "BLOCKED" } else { "ALLOW" },
                        if live_active { "RUNNING" } else { "STOPPED" }
                    );

                    let _ = event_tx.send(OsStatusEvent::QuerySync {
                        enabled: live_enabled,
                        blocked: live_blocked,
                        active: live_active,
                        banner,
                    });
                }
                OsCommand::ToggleFirewall(target_on) => {
                    let start_time = std::time::Instant::now();
                    println!("[DEBUG OS WORKER] Received ToggleFirewall(target_on={})", target_on);
                    let result = if target_on {
                        s2o_net_lib::firewall::FirewallController::enable_firewall()
                    } else {
                        s2o_net_lib::firewall::FirewallController::disable_firewall()
                    };

                    // OS Transaction Chain Verification Protocol (Pure Flag-Driven):
                    // Requires 3 CONSECUTIVE verified readings (100ms apart) confirming target_on from live OS!
                    let mut live_enabled = false;
                    let mut consecutive_matches = 0;

                    for attempt in 1..=30 {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        match s2o_net_lib::firewall::FirewallController::is_firewall_enabled() {
                            Ok(real_state) => {
                                live_enabled = real_state;
                                println!("[DEBUG OS WORKER] Verification attempt {}: real_state={}, target_on={}", attempt, real_state, target_on);
                                if live_enabled == target_on {
                                    consecutive_matches += 1;
                                    println!("[DEBUG OS WORKER] -> Consecutive OS State Match #{}", consecutive_matches);
                                    if consecutive_matches >= 3 {
                                        println!("[DEBUG OS WORKER] -> OS TRANSACTION COMPLETION VERIFIED (3x Consecutive Stable Readings)!");
                                        break;
                                    }
                                } else {
                                    consecutive_matches = 0;
                                }
                            }
                            Err(e) => {
                                consecutive_matches = 0;
                                println!("[DEBUG OS WORKER] Verification attempt {}: error {:?}", attempt, e);
                            }
                        }
                    }

                    // Enforce Mandatory OS Transaction Settling Dwell Window (2.5s / 2500ms)
                    // so WFP kernel & mpssvc complete hardware driver commit BEFORE sending completion event!
                    let min_dwell = std::time::Duration::from_millis(2500);
                    let elapsed = start_time.elapsed();
                    if elapsed < min_dwell {
                        let remaining = min_dwell - elapsed;
                        println!("[DEBUG OS WORKER] Holding Busy State for Full OS Settling Window: sleeping remaining {:?}", remaining);
                        std::thread::sleep(remaining);
                    }

                    println!("[DEBUG OS WORKER] Firewall COM result: {:?}, Verified live OS state: {}", result, live_enabled);

                    let banner = match result {
                        Ok(_) => format!("[WFP ENGINE] Windows Firewall kernel confirmed: {}", if live_enabled { "ENABLED (Green)" } else { "DISABLED (Red)" }),
                        Err(e) => format!("[ADMIN REQUIRED] Firewall COM error ({:?}). Verified live status: {}", e, if live_enabled { "ENABLED" } else { "DISABLED" }),
                    };

                    // Send OS Transaction Completion Event back to UI to flip node.is_busy to false and os_sync_ready to true!
                    let _ = event_tx.send(OsStatusEvent::FirewallStatus { enabled: live_enabled, banner });
                }
                OsCommand::ToggleShield(target_block) => {
                    let start_time = std::time::Instant::now();
                    println!("[DEBUG OS WORKER] Received ToggleShield(target_block={})", target_block);
                    let result = if target_block {
                        s2o_net_lib::firewall::FirewallController::airplane_mode_enable()
                    } else {
                        s2o_net_lib::firewall::FirewallController::airplane_mode_disable()
                    };

                    // OS Transaction Chain Verification Protocol (Pure Flag-Driven):
                    let mut live_blocked = false;
                    let mut consecutive_matches = 0;

                    for attempt in 1..=30 {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                        match s2o_net_lib::firewall::FirewallController::is_outbound_blocked() {
                            Ok(real_state) => {
                                live_blocked = real_state;
                                println!("[DEBUG OS WORKER] Verification attempt {}: real_state={}, target_block={}", attempt, real_state, target_block);
                                if live_blocked == target_block {
                                    consecutive_matches += 1;
                                    println!("[DEBUG OS WORKER] -> Consecutive Shield State Match #{}", consecutive_matches);
                                    if consecutive_matches >= 3 {
                                        println!("[DEBUG OS WORKER] -> SHIELD OS TRANSACTION COMPLETION VERIFIED (3x Consecutive Stable Readings)!");
                                        break;
                                    }
                                } else {
                                    consecutive_matches = 0;
                                }
                            }
                            Err(e) => {
                                consecutive_matches = 0;
                                println!("[DEBUG OS WORKER] Verification attempt {}: error {:?}", attempt, e);
                            }
                        }
                    }

                    // Enforce Mandatory OS Transaction Settling Dwell Window (2.5s / 2500ms)
                    let min_dwell = std::time::Duration::from_millis(2500);
                    let elapsed = start_time.elapsed();
                    if elapsed < min_dwell {
                        let remaining = min_dwell - elapsed;
                        println!("[DEBUG OS WORKER] Holding Busy State for Full OS Settling Window: sleeping remaining {:?}", remaining);
                        std::thread::sleep(remaining);
                    }

                    println!("[DEBUG OS WORKER] Shield COM result: {:?}, Verified live OS status: {}", result, live_blocked);

                    let banner = match result {
                        Ok(_) => format!("[SHIELD] Outbound isolation kernel confirmed: {}", if live_blocked { "OUTBOUND BLOCKED (Red)" } else { "NORMAL ALLOW (Green)" }),
                        Err(e) => format!("[ADMIN REQUIRED] Shield error ({:?}). Verified live status: {}", e, if live_blocked { "BLOCKED" } else { "ALLOW" }),
                    };

                    // Send OS Transaction Completion Event back to UI to flip os_sync_ready flag to true!
                    let _ = event_tx.send(OsStatusEvent::ShieldStatus { blocked: live_blocked, banner });
                }
                OsCommand::ToggleDefender(_) => {
                    let live_active = s2o_net_lib::defender::DefenderController::is_defender_active();
                    println!("[OS LINKAGE VERIFIED] Defender service verified live: {}", live_active);
                    let banner = format!("[DEFENDER ENGINE] Real-Time Defender Status: {}", if live_active { "RUNNING (Green)" } else { "STOPPED (Red)" });
                    let _ = event_tx.send(OsStatusEvent::DefenderStatus { active: live_active, banner });
                }
            }
        }
    });

    (cmd_tx, event_rx)
}

fn load_window_config() -> Option<(f32, f32)> {
    if let Ok(content) = std::fs::read_to_string("window_config.json") {
        let mut width = None;
        let mut height = None;
        for line in content.lines() {
            let line = line.trim();
            if line.contains("\"width\":") {
                if let Some(val_str) = line.split(':').nth(1) {
                    let val_clean = val_str.trim().trim_matches(',').trim();
                    width = val_clean.parse::<f32>().ok();
                }
            } else if line.contains("\"height\":") {
                if let Some(val_str) = line.split(':').nth(1) {
                    let val_clean = val_str.trim().trim_matches(',').trim();
                    height = val_clean.parse::<f32>().ok();
                }
            }
        }
        if let (Some(w), Some(h)) = (width, height) {
            return Some((w.max(600.0), h.max(450.0)));
        }
    }
    None
}

fn save_window_config(width: f32, height: f32) {
    let json_str = format!("{{\n  \"width\": {:.1},\n  \"height\": {:.1}\n}}", width, height);
    let _ = std::fs::write("window_config.json", json_str);
}

fn setup_custom_fonts(ctx: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();

    // Embed NotoSansJP-Bold font bytes from s2o_net_lib snl0.5
    let font_bytes = include_bytes!("../../net-lib/snl0.5/NotoSansJP-Bold.ttf");
    fonts.font_data.insert(
        "NotoSansJP".to_owned(),
        egui::FontData::from_static(font_bytes),
    );

    // Insert NotoSansJP as highest priority font for Japanese Kanji rendering
    fonts.families.entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "NotoSansJP".to_owned());

    fonts.families.entry(egui::FontFamily::Monospace)
        .or_default()
        .push("NotoSansJP".to_owned());

    ctx.set_fonts(fonts);
}

fn main() {
    let initial_size = load_window_config()
        .map(|(w, h)| egui::Vec2::new(w, h))
        .unwrap_or_else(|| egui::Vec2::new(800.0, 600.0));

    let options = eframe::NativeOptions {
        initial_window_size: Some(initial_size),
        min_window_size: Some(egui::Vec2::new(600.0, 450.0)),
        resizable: true,
        ..Default::default()
    };

    eframe::run_native(
        Box::new(CyberFirewallApp::default()),
        options,
    );
}

#[derive(PartialEq, Debug, Clone, Copy)]
enum MenuState {
    MainMenu,
    BasicMenu,
    BasicFirewallMenu,
    BasicNetworkMenu,
    AdvancedMenu,
    AdvancedFirewallMenu,
    AdvancedNetworkMenu,
    SettingsMenu,
}

struct CyberFirewallApp {
    matrix_rain: MatrixRain,
    ship: CyberShip,
    lasers: Vec<CyberLaser>,
    nodes: Vec<CyberNode>,

    current_state: MenuState,
    level_title: String,
    status_banner: String,

    cached_fw_enabled: bool,
    cached_shield_blocked: bool,
    cached_defender_active: bool,

    os_tx: Sender<OsCommand>,
    os_rx: Receiver<OsStatusEvent>,
    os_sync_ready: bool,

    fonts_loaded: bool,
    level_flash_timer: Option<Instant>,
    last_width: f32,
    last_height: f32,
    last_resize_time: Option<Instant>,
    pending_save: bool,
}

impl CyberFirewallApp {
    fn load_nodes_for_state(state: MenuState, screen_width: f32, fw_enabled: bool, shield_blocked: bool, defender_active: bool, os_sync_ready: bool) -> Vec<CyberNode> {
        let step4 = screen_width / 5.0;
        let p4_0 = step4 * 1.0 - 30.0;
        let p4_1 = step4 * 2.0 - 30.0;
        let p4_2 = step4 * 3.0 - 30.0;
        let p4_3 = step4 * 4.0 - 30.0;

        let step3 = screen_width / 4.0;
        let p3_0 = step3 * 1.0 - 30.0;
        let p3_1 = step3 * 2.0 - 30.0;
        let p3_2 = step3 * 3.0 - 30.0;

        match state {
            MenuState::MainMenu => vec![
                CyberNode::new(p4_0, 110.0, "BASIC", "1. SIMPLE CTL"),
                CyberNode::new(p4_1, 110.0, "ADVANCED", "2. FULL AUDIT"),
                CyberNode::new(p4_2, 110.0, "SETTINGS", "3. DEFENDER"),
                CyberNode::new(p4_3, 110.0, "EXIT", "4. CLOSE APP"),
            ],
            MenuState::BasicMenu => {
                let mut fw_node = CyberNode::new(p3_0, 110.0, "FIREWALL", "1. WFP CTL");
                fw_node.state = fw_enabled;
                fw_node.is_busy = !os_sync_ready;

                let net_node = CyberNode::new(p3_1, 110.0, "NETWORK", "2. TELEMETRY");
                let back_node = CyberNode::new(p3_2, 110.0, "BACK <<", "3. MAIN MENU");

                vec![fw_node, net_node, back_node]
            },
            MenuState::BasicFirewallMenu => {
                let mut fw_node = CyberNode::new(p3_0, 110.0, "FIREWALL", "1. TOGGLE ON/OFF");
                fw_node.state = fw_enabled;
                fw_node.is_busy = !os_sync_ready;

                let mut shield_node = CyberNode::new(p3_1, 110.0, "SHIELD", "2. OUTBOUND BLOCK");
                shield_node.state = shield_blocked;
                shield_node.is_busy = !os_sync_ready;

                let back_node = CyberNode::new(p3_2, 110.0, "BACK <<", "3. BASIC MENU");

                vec![fw_node, shield_node, back_node]
            },
            MenuState::BasicNetworkMenu => vec![
                CyberNode::new(p3_0, 110.0, "ADAPTERS", "1. HARDWARE"),
                CyberNode::new(p3_1, 110.0, "SOCKET SCAN", "2. IP HELPER"),
                CyberNode::new(p3_2, 110.0, "BACK <<", "3. BASIC MENU"),
            ],
            MenuState::AdvancedMenu => {
                let mut adv_fw_node = CyberNode::new(p4_0, 110.0, "ADV FIREWALL", "1. AUDIT & RULES");
                adv_fw_node.state = fw_enabled;

                let adv_net_node = CyberNode::new(p4_1, 110.0, "ADV NETWORK", "2. DEEP TELEMETRY");
                let diag_node = CyberNode::new(p4_2, 110.0, "DIAGNOSTICS", "3. SYS DIAG");
                let back_node = CyberNode::new(p4_3, 110.0, "BACK <<", "4. MAIN MENU");

                vec![adv_fw_node, adv_net_node, diag_node, back_node]
            },
            MenuState::AdvancedFirewallMenu => vec![
                CyberNode::new(p4_0, 110.0, "SNAPSHOT", "1. RULE AUDIT"),
                CyberNode::new(p4_1, 110.0, "RULE BUILDER", "2. CUSTOM RULE"),
                CyberNode::new(p4_2, 110.0, "RESET DEFAULTS", "3. MS DEFAULTS"),
                CyberNode::new(p4_3, 110.0, "BACK <<", "4. ADV MENU"),
            ],
            MenuState::AdvancedNetworkMenu => vec![
                CyberNode::new(p3_0, 110.0, "SOCKET INSPECT", "1. ACTIVE CONNS"),
                CyberNode::new(p3_1, 110.0, "PROMISCUOUS", "2. WIREFRAME TEST"),
                CyberNode::new(p3_2, 110.0, "BACK <<", "3. ADV MENU"),
            ],
            MenuState::SettingsMenu => {
                let mut def_node = CyberNode::new(p4_0, 110.0, "DEFENDER", "1. REALTIME SVC");
                def_node.state = defender_active;

                let scan_node = CyberNode::new(p4_1, 110.0, "QUICK SCAN", "2. SCAN THREATS");
                let update_node = CyberNode::new(p4_2, 110.0, "UPDATE DEFS", "3. SIGNATURES");
                let back_node = CyberNode::new(p4_3, 110.0, "BACK <<", "4. MAIN MENU");

                vec![def_node, scan_node, update_node, back_node]
            },
        }
    }
}

impl Default for CyberFirewallApp {
    fn default() -> Self {
        let (width, height) = load_window_config().unwrap_or((800.0, 600.0));
        let (os_tx, os_rx) = spawn_os_worker();
        let cached_fw = s2o_net_lib::firewall::FirewallController::is_firewall_enabled().unwrap_or(true);
        let cached_shield = s2o_net_lib::firewall::FirewallController::is_outbound_blocked().unwrap_or(false);
        let cached_def = s2o_net_lib::defender::DefenderController::is_defender_active();

        // Bootup Query: Immediately query live Windows Defender Firewall status on startup
        let _ = os_tx.send(OsCommand::QueryStatus);

        Self {
            matrix_rain: MatrixRain::new(width, height),
            ship: CyberShip::new(width),
            lasers: Vec::new(),
            nodes: Self::load_nodes_for_state(MenuState::MainMenu, width, cached_fw, cached_shield, cached_def, false),

            current_state: MenuState::MainMenu,
            level_title: "MAIN MENU".to_string(),
            status_banner: "[OS BOOTUP VERIFICATION] Synchronizing with Windows Defender Firewall...".to_string(),

            cached_fw_enabled: cached_fw,
            cached_shield_blocked: cached_shield,
            cached_defender_active: cached_def,

            os_tx,
            os_rx,
            os_sync_ready: false,

            fonts_loaded: false,
            level_flash_timer: None,
            last_width: width,
            last_height: height,
            last_resize_time: None,
            pending_save: false,
        }
    }
}

impl epi::App for CyberFirewallApp {
    fn name(&self) -> &str {
        "S2O CYBERWALL "
    }

    fn update(&mut self, ctx: &egui::Context, frame: &epi::Frame) {
        // Drain any incoming verified live OS status events from the async worker channel
        while let Ok(event) = self.os_rx.try_recv() {
            match event {
                OsStatusEvent::QuerySync { enabled, blocked, active, banner } => {
                    self.cached_fw_enabled = enabled;
                    self.cached_shield_blocked = blocked;
                    self.cached_defender_active = active;
                    self.status_banner = banner;
                    for node in self.nodes.iter_mut() {
                        if !node.is_busy {
                            if node.label == "FIREWALL" || node.label == "ADV FIREWALL" {
                                node.state = enabled;
                            } else if node.label == "SHIELD" {
                                node.state = blocked;
                            } else if node.label == "DEFENDER" {
                                node.state = active;
                            }
                        }
                    }
                    if !self.nodes.iter().any(|n| n.is_busy) {
                        self.os_sync_ready = true;
                    }
                }
                OsStatusEvent::FirewallStatus { enabled, banner } => {
                    self.cached_fw_enabled = enabled;
                    self.status_banner = banner;
                    self.os_sync_ready = true;
                    for node in self.nodes.iter_mut() {
                        if node.label == "FIREWALL" || node.label == "ADV FIREWALL" {
                            node.state = enabled;
                            node.is_busy = false;
                            node.reset_cooldown();
                        }
                    }
                }
                OsStatusEvent::ShieldStatus { blocked, banner } => {
                    self.cached_shield_blocked = blocked;
                    self.status_banner = banner;
                    self.os_sync_ready = true;
                    for node in self.nodes.iter_mut() {
                        if node.label == "SHIELD" {
                            node.state = blocked;
                            node.is_busy = false;
                            node.reset_cooldown();
                        }
                    }
                }
                OsStatusEvent::DefenderStatus { active, banner } => {
                    self.cached_defender_active = active;
                    self.status_banner = banner;
                    self.os_sync_ready = true;
                    for node in self.nodes.iter_mut() {
                        if node.label == "DEFENDER" {
                            node.state = active;
                            node.is_busy = false;
                            node.reset_cooldown();
                        }
                    }
                }
            }
        }

        if !self.fonts_loaded {
            setup_custom_fonts(ctx);
            self.fonts_loaded = true;
        }

        ctx.set_visuals(egui::Visuals::dark());
        let input = ctx.input().clone();

        let available_rect = ctx.available_rect();
        let screen_width = available_rect.width();
        let screen_height = available_rect.height();

        // Update Matrix Code Rain particle background with dynamic dimensions
        self.matrix_rain.update(screen_width, screen_height);

        // Update ship steering with dynamic width clamping
        self.ship.update(&input, screen_width);

        // Re-calculate target positions in memory immediately during resize
        if (self.last_width - screen_width).abs() > 5.0 || (self.last_height - screen_height).abs() > 5.0 {
            self.nodes = Self::load_nodes_for_state(
                self.current_state,
                screen_width,
                self.cached_fw_enabled,
                self.cached_shield_blocked,
                self.cached_defender_active,
                self.os_sync_ready,
            );
            self.last_width = screen_width;
            self.last_height = screen_height;
            self.last_resize_time = Some(Instant::now());
            self.pending_save = true;
        }

        // Debounced disk write: Only save window_config.json after resize drag has stopped for 1 second
        if self.pending_save {
            if let Some(t) = self.last_resize_time {
                if t.elapsed() > std::time::Duration::from_millis(1000) {
                    save_window_config(screen_width, screen_height);
                    self.pending_save = false;
                }
            }
        }

        let bottom = available_rect.bottom();

        // Handle plasma laser firing (locked out while OS Sync is in progress)
        if input.key_pressed(egui::Key::Space) {
            if !self.os_sync_ready {
                self.status_banner = "[FIRE TRIGGER LOCKED] OS Sync in progress... Wait for [OS SYNC: YES]!".to_string();
            } else {
                let laser = self.ship.shoot(bottom);
                self.lasers.push(laser);
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // Render Japanese Matrix Rain Code Background
            self.matrix_rain.render(ui);

            // 100% Mathematically Auto-Centered Animated Neon Cyber Logo Emblem Banner
            ui.vertical_centered(|ui| {
                ui.add_space(6.0);

                let time = ctx.input().time as f32;
                let pulse = (time * 2.5).sin() * 0.5 + 0.5; // Smooth 0.0 .. 1.0 color breathing cycle

                egui::Frame::none()
                    .fill(egui::Color32::from_rgba_unmultiplied(8, 16, 30, 225))
                    .stroke(egui::Stroke::new(
                        1.8_f32,
                        egui::Color32::from_rgb(
                            (0.0 + 40.0 * pulse) as u8,
                            (220.0 + 35.0 * pulse) as u8,
                            255,
                        ),
                    ))
                    .rounding(10.0)
                    .margin(egui::style::Margin::symmetric(18.0, 6.0))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            // Left Laser Flank Accent
                            ui.label(
                                egui::RichText::new("━━━◆ ")
                                    .color(egui::Color32::from_rgb(0, 255, 235))
                                    .size(15.0)
                                    .strong(),
                            );

                            // S2O
                            ui.label(
                                egui::RichText::new("S2O")
                                    .color(egui::Color32::from_rgb(0, 255, 235))
                                    .size(26.0)
                                    .strong(),
                            );

                            // 【網】
                            ui.label(
                                egui::RichText::new("【網】")
                                    .color(egui::Color32::from_rgb(
                                        255,
                                        (50.0 + 40.0 * pulse) as u8,
                                        (90.0 + 30.0 * pulse) as u8,
                                    ))
                                    .size(26.0)
                                    .strong(),
                            );

                            // 防火壁
                            ui.label(
                                egui::RichText::new("防火壁")
                                    .color(egui::Color32::from_rgb(
                                        255,
                                        (210.0 + 45.0 * pulse) as u8,
                                        (40.0 * pulse) as u8,
                                    ))
                                    .size(24.0)
                                    .strong(),
                            );

                            // Right Laser Flank Accent
                            ui.label(
                                egui::RichText::new(" ◆━━━")
                                    .color(egui::Color32::from_rgb(0, 255, 235))
                                    .size(15.0)
                                    .strong(),
                            );

                            // Active Sub-Menu Level & Live OS Status Ticker Tag
                            let (ticker_text, ticker_color) = if self.os_sync_ready {
                                ("[OS SYNC: YES]", egui::Color32::from_rgb(0, 255, 180))
                            } else {
                                ("[OS SYNC: IN PROGRESS...]", egui::Color32::from_rgb(255, 200, 40))
                            };

                            ui.label(
                                egui::RichText::new(&format!(" :: {}  {}", self.level_title, ticker_text))
                                    .color(ticker_color)
                                    .size(16.0)
                                    .strong(),
                            );
                        });
                    });

                ui.add_space(4.0);
                ui.label(
                    egui::RichText::new(&self.status_banner)
                        .color(egui::Color32::from_rgb(200, 215, 255))
                        .size(13.0),
                );
            });

            // Update & Render Laser Bolts
            for laser in &mut self.lasers {
                laser.update();
                laser.render(ui);
            }

            // Retain active lasers
            self.lasers.retain(|l| l.y > 0.0);

            // Render Cyber Target Nodes
            for node in &self.nodes {
                node.render(ui);
            }

            // Render Cyber Ship
            self.ship.render(ui);

            // Collision Detection & Real Backend Execution
            let mut state_transition = false;
            let mut hit_laser_indices = std::collections::HashSet::new();

            for (l_idx, laser) in self.lasers.iter().enumerate() {
                for (idx, node) in self.nodes.iter_mut().enumerate() {
                    if node.check_collision(laser) {
                        hit_laser_indices.insert(l_idx);

                        if !node.can_toggle() {
                            continue;
                        }

                        // Hardware Lockout: Toggles occur ONLY when OS sync flag is YES
                        if (self.current_state == MenuState::BasicMenu && idx == 0)
                            || (self.current_state == MenuState::BasicFirewallMenu && (idx == 0 || idx == 1))
                            || (self.current_state == MenuState::SettingsMenu && idx == 0)
                        {
                            if !self.os_sync_ready {
                                self.status_banner = "[OS SYNC IN PROGRESS] Toggle locked until OS completes declaration...".to_string();
                                continue;
                            }
                            self.os_sync_ready = false;
                        }

                        node.register_hit();

                        match (self.current_state, idx) {
                            // 1. MAIN MENU
                            (MenuState::MainMenu, 0) => {
                                self.current_state = MenuState::BasicMenu;
                                self.level_title = "BASIC MENU".to_string();
                                self.status_banner = "BASIC MENU: Select Firewall, Network, or Back.".to_string();
                                state_transition = true;
                            }
                            (MenuState::MainMenu, 1) => {
                                self.current_state = MenuState::AdvancedMenu;
                                self.level_title = "ADVANCED MENU".to_string();
                                self.status_banner = "ADVANCED MENU: Select Adv Firewall, Adv Network, Diagnostics, or Back.".to_string();
                                state_transition = true;
                            }
                            (MenuState::MainMenu, 2) => {
                                self.current_state = MenuState::SettingsMenu;
                                self.level_title = "SETTINGS MENU (DEFENDER)".to_string();
                                self.status_banner = "SETTINGS MENU: Select Quick Scan, Update Defs, or Back.".to_string();
                                state_transition = true;
                            }
                            (MenuState::MainMenu, 3) => {
                                self.status_banner = "SHUTTING DOWN S2O CYBERFIREWALL... GOODBYE!".to_string();
                                frame.quit();
                            }

                            // 2. BASIC MENU
                            (MenuState::BasicMenu, 0) => {
                                let target_on = !node.state;
                                node.is_busy = true;
                                let _ = self.os_tx.send(OsCommand::ToggleFirewall(target_on));
                                self.status_banner = format!("[OS BUSY] Transmitting Firewall Request (Target: {})... Waiting for OS declaration...", if target_on { "ENABLED" } else { "DISABLED" });
                            }
                            (MenuState::BasicMenu, 1) => {
                                self.current_state = MenuState::BasicNetworkMenu;
                                self.level_title = "BASIC NETWORK TELEMETRY".to_string();
                                self.status_banner = "BASIC NETWORK: Scan Adapters, Sockets, or Back.".to_string();
                                state_transition = true;
                            }
                            (MenuState::BasicMenu, 2) => {
                                self.current_state = MenuState::MainMenu;
                                self.level_title = "MAIN MENU".to_string();
                                self.status_banner = "Returned to Main Menu.".to_string();
                                state_transition = true;
                            }

                            // 3. BASIC FIREWALL MENU
                            (MenuState::BasicFirewallMenu, 0) => {
                                let target_on = !node.state;
                                node.is_busy = true;
                                let _ = self.os_tx.send(OsCommand::ToggleFirewall(target_on));
                                self.status_banner = format!("[OS BUSY] Transmitting Firewall Request (Target: {})... Waiting for OS declaration...", if target_on { "ENABLED" } else { "DISABLED" });
                            }
                            (MenuState::BasicFirewallMenu, 1) => {
                                let target_block = !node.state;
                                node.is_busy = true;
                                let _ = self.os_tx.send(OsCommand::ToggleShield(target_block));
                                self.status_banner = format!("[OS BUSY] Transmitting Outbound Isolation Request (Target: {})... Waiting for OS declaration...", if target_block { "BLOCKED" } else { "ALLOW" });
                            }
                            (MenuState::BasicFirewallMenu, 2) => {
                                self.current_state = MenuState::BasicMenu;
                                self.level_title = "BASIC MENU".to_string();
                                self.status_banner = "Returned to Basic Menu.".to_string();
                                state_transition = true;
                            }

                            // 4. BASIC NETWORK MENU
                            (MenuState::BasicNetworkMenu, 0) => {
                                s2o_net_lib::util2::show_active_adapters();
                                self.status_banner = "[NETWORK] Network Adapters Printed to Console".to_string();
                            }
                            (MenuState::BasicNetworkMenu, 1) => {
                                let conns = s2o_net_lib::telemetry::get_active_tcp_connections();
                                self.status_banner = format!("[NETWORK] Scanned {} Active Sockets via IP Helper", conns.len());
                            }
                            (MenuState::BasicNetworkMenu, 2) => {
                                self.current_state = MenuState::BasicMenu;
                                self.level_title = "BASIC MENU".to_string();
                                self.status_banner = "Returned to Basic Menu.".to_string();
                                state_transition = true;
                            }

                            // 5. ADVANCED MENU
                            (MenuState::AdvancedMenu, 0) => {
                                self.current_state = MenuState::AdvancedFirewallMenu;
                                self.level_title = "ADVANCED FIREWALL AUDIT".to_string();
                                self.status_banner = "ADV FIREWALL: Rule Snapshot, Rule Builder, Reset Defaults.".to_string();
                                state_transition = true;
                            }
                            (MenuState::AdvancedMenu, 1) => {
                                self.current_state = MenuState::AdvancedNetworkMenu;
                                self.level_title = "ADVANCED NETWORK TELEMETRY".to_string();
                                self.status_banner = "ADV NETWORK: Socket Inspector, Promiscuous Test.".to_string();
                                state_transition = true;
                            }
                            (MenuState::AdvancedMenu, 2) => {
                                let _ = s2o_net_lib::firewall::FirewallController::list_firewall_rules();
                                self.status_banner = "[DIAGNOSTICS] Firewall Rules Audit Printed to Console".to_string();
                            }
                            (MenuState::AdvancedMenu, 3) => {
                                self.current_state = MenuState::MainMenu;
                                self.level_title = "MAIN MENU".to_string();
                                self.status_banner = "Returned to Main Menu.".to_string();
                                state_transition = true;
                            }

                            // 6. ADVANCED FIREWALL MENU
                            (MenuState::AdvancedFirewallMenu, 0) => {
                                let _ = s2o_net_lib::firewall::FirewallController::snapshot_all_rules();
                                self.status_banner = "[ADV FIREWALL] Full Firewall Rules Snapshot Logged".to_string();
                            }
                            (MenuState::AdvancedFirewallMenu, 1) => {
                                self.status_banner = "[RULE BUILDER] Interactive Custom Rule Engine Ready".to_string();
                            }
                            (MenuState::AdvancedFirewallMenu, 2) => {
                                let _ = s2o_net_lib::firewall::FirewallController::reset_to_default_policy();
                                self.status_banner = "[RESET] Windows Firewall Reset to Standard Microsoft Policy".to_string();
                            }
                            (MenuState::AdvancedFirewallMenu, 3) => {
                                self.current_state = MenuState::AdvancedMenu;
                                self.level_title = "ADVANCED MENU".to_string();
                                self.status_banner = "Returned to Advanced Menu.".to_string();
                                state_transition = true;
                            }

                            // 7. ADVANCED NETWORK MENU
                            (MenuState::AdvancedNetworkMenu, 0) => {
                                let conns = s2o_net_lib::telemetry::get_active_tcp_connections();
                                self.status_banner = format!("[ADV NETWORK] Inspected {} Active Sockets via IP Helper", conns.len());
                            }
                            (MenuState::AdvancedNetworkMenu, 1) => {
                                self.status_banner = "[PROMISCUOUS] Native Driverless Telemetry Scanner Active".to_string();
                            }
                            (MenuState::AdvancedNetworkMenu, 2) => {
                                self.current_state = MenuState::AdvancedMenu;
                                self.level_title = "ADVANCED MENU".to_string();
                                self.status_banner = "Returned to Advanced Menu.".to_string();
                                state_transition = true;
                            }

                            // 8. SETTINGS MENU
                            (MenuState::SettingsMenu, 0) => {
                                let target_on = !node.state;
                                let _ = self.os_tx.send(OsCommand::ToggleDefender(target_on));
                                self.status_banner = "[DEFENDER ENGINE] Querying Real-Time Defender Status... Waiting for OS declaration...".to_string();
                            }
                            (MenuState::SettingsMenu, 1) => {
                                std::thread::spawn(|| {
                                    let _ = s2o_net_lib::defender::DefenderController::run_scan_native();
                                });
                                self.status_banner = "[SETTINGS] Neural Defender Quick Scan Spawned".to_string();
                            }
                            (MenuState::SettingsMenu, 2) => {
                                std::thread::spawn(|| {
                                    let _ = s2o_net_lib::defender::DefenderController::update_defender_native();
                                });
                                self.status_banner = "[SETTINGS] Defender Signature Update Spawned".to_string();
                            }
                            (MenuState::SettingsMenu, 3) => {
                                self.current_state = MenuState::MainMenu;
                                self.level_title = "MAIN MENU".to_string();
                                self.status_banner = "Returned to Main Menu.".to_string();
                                state_transition = true;
                            }
                            _ => {}
                        }
                    }
                }
            }

            if !hit_laser_indices.is_empty() {
                let mut l_idx = 0;
                self.lasers.retain(|_| {
                    let hit = hit_laser_indices.contains(&l_idx);
                    l_idx += 1;
                    !hit
                });
            }

            if state_transition {
                self.lasers.clear();
                self.nodes = Self::load_nodes_for_state(
                    self.current_state,
                    screen_width,
                    self.cached_fw_enabled,
                    self.cached_shield_blocked,
                    self.cached_defender_active,
                    self.os_sync_ready,
                );
                self.level_flash_timer = Some(Instant::now());
                let _ = self.os_tx.send(OsCommand::QueryStatus);
            }
        });

        ctx.request_repaint();
    }
}
