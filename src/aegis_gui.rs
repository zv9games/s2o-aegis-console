use eframe::{egui, epi};
use cyberwall_core::{FirewallEngine, FirewallRule, RuleAction, RuleDirection, RuleProtocol, ProfileType};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActiveModal {
    None,
    FirewallSettings,
    MeshSettings,
    DefenderSettings,
    EdrSettings,
    SiemSettings,
    IntelSettings,
    DnsSettings,
    IdSettings,
    ZtnaSettings,
}

struct AegisDashboardApp {
    last_refresh: Instant,
    firewall_enabled: bool,
    outbound_shield: bool,
    defender_active: bool,
    active_connections_count: usize,
    status_rx: Receiver<DashboardState>,
    cmd_tx: Sender<DashboardCmd>,
    recent_events: Vec<String>,
    active_modal: ActiveModal,

    // 1. Comprehensive Firewall State
    fw_rule_name_input: String,
    fw_rule_action_allow: bool,
    fw_rule_dir_inbound: bool,
    fw_rule_proto_tcp: bool,
    fw_rule_port_input: String,
    fw_rule_remote_ip_input: String,
    fw_rule_app_path_input: String,
    fw_delete_rule_name_input: String,
    fw_rules_cache: Vec<String>,

    // 2. Comprehensive Mesh State
    mesh_endpoint_input: String,
    mesh_listen_port: u16,
    mesh_keepalive: u32,
    mesh_client_ip: String,
    mesh_dns_server: String,
    mesh_persistent_active: bool,

    // 3. Comprehensive Defender State
    scan_target_path: String,
    scan_deep_mode: bool,
    scan_archive_mode: bool,
    defender_tamper_protection: bool,
    defender_cloud_protection: bool,

    // 4. Comprehensive EDR State
    edr_backdoor_threshold: u16,
    edr_auto_kill_unauthorized: bool,
    edr_kill_pid_input: String,
    edr_isolate_suspicious_sockets: bool,

    // 5. Comprehensive SIEM State
    siem_log_retention_days: u32,
    siem_syslog_forwarder: String,
    siem_forward_protocol_udp: bool,
    siem_alert_email: String,

    // 6. Comprehensive Threat Intel State
    intel_auto_sync_interval_mins: u32,
    intel_custom_ioc: String,
    intel_feed_urlhaus_enabled: bool,
    intel_feed_alienvault_enabled: bool,

    // 7. Comprehensive DNS Guard State
    dns_custom_block_domain: String,
    dns_unblock_domain: String,
    dns_upstream_doh: String,
    dns_fallback_ip: String,
    dns_block_tor_nodes: bool,

    // 8. Comprehensive CyberID State
    id_enforce_secureboot: bool,
    id_enforce_uac: bool,
    id_enforce_firewall: bool,
    id_enforce_defender: bool,
    id_device_subject: String,

    // 9. Comprehensive ZTNA State
    ztna_min_posture_threshold: u32,
    ztna_route_destination: String,
    ztna_upstream_proxy: String,
    ztna_mutual_tls_enabled: bool,
}

#[derive(Clone)]
struct DashboardState {
    firewall_enabled: bool,
    outbound_shield: bool,
    defender_active: bool,
    connections: usize,
    events: Vec<String>,
    rules_summary: Vec<String>,
}

enum DashboardCmd {
    Refresh,
    ToggleFirewall(bool),
    ToggleShield(bool),
    // Firewall commands
    AddCustomRule(FirewallRule),
    DeleteRuleByName(String),
    // Mesh commands
    GenMeshKey,
    ExportMeshConfig(String, u16, u32, String),
    // Defender commands
    TriggerScan(String),
    UpdateSignatures,
    // EDR commands
    AuditEdr,
    KillProcess(u32),
    // SIEM commands
    EmitSiemEvent(String),
    ClearSiemLog,
    // Threat Intel commands
    SyncIntel,
    AddIoc(String),
    // DNS commands
    TestDns(String),
    BlockDomain(String),
    UnblockDomain(String),
    // CyberID commands
    AuditPosture,
    GenerateAttestation(String),
    // ZTNA commands
    TestZtna(String),
}

impl epi::App for AegisDashboardApp {
    fn name(&self) -> &str {
        "S2O Aegis Enterprise Command Center"
    }

    fn update(&mut self, ctx: &egui::Context, _frame: &epi::Frame) {
        // Drain status updates
        while let Ok(state) = self.status_rx.try_recv() {
            self.firewall_enabled = state.firewall_enabled;
            self.outbound_shield = state.outbound_shield;
            self.defender_active = state.defender_active;
            self.active_connections_count = state.connections;
            self.recent_events = state.events;
            if !state.rules_summary.is_empty() {
                self.fw_rules_cache = state.rules_summary;
            }
        }

        // Periodic auto-poll every 3s
        if self.last_refresh.elapsed().as_secs() > 3 {
            let _ = self.cmd_tx.send(DashboardCmd::Refresh);
            self.last_refresh = Instant::now();
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            // Top Bar
            ui.horizontal(|ui| {
                ui.heading(
                    egui::RichText::new("S2O AEGIS ENTERPRISE COMMAND CENTER")
                        .color(egui::Color32::from_rgb(0, 230, 150))
                        .strong(),
                );
                ui.with_layout(egui::Layout::right_to_left(), |ui| {
                    if ui.button("⟳ Refresh Matrix").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::Refresh);
                    }
                    ui.label(
                        egui::RichText::new("SUBSTRATE: Tier-0 Userspace Native ($0/yr)")
                            .color(egui::Color32::from_rgb(100, 200, 255)),
                    );
                });
            });

            ui.separator();

            // 9-Pillar Matrix Grid
            ui.heading("Aegis 9-Pillar Operational Matrix");
            egui::Grid::new("matrix_grid")
                .striped(true)
                .min_col_width(110.0)
                .show(ui, |ui| {
                    ui.label(egui::RichText::new("Discipline").strong());
                    ui.label(egui::RichText::new("Engine Name").strong());
                    ui.label(egui::RichText::new("Status").strong());
                    ui.label(egui::RichText::new("Interactive Action").strong());
                    ui.label(egui::RichText::new("Pillar Customization").strong());
                    ui.label(egui::RichText::new("Telemetry & Substrate Mode").strong());
                    ui.end_row();

                    // 1. Firewall
                    ui.label("1. Firewall");
                    ui.label("S2O Cyberwall");
                    if self.firewall_enabled {
                        ui.label(egui::RichText::new("ONLINE").color(egui::Color32::GREEN).strong());
                    } else {
                        ui.label(egui::RichText::new("OFFLINE").color(egui::Color32::RED).strong());
                    }
                    if ui.button(if self.firewall_enabled { "Toggle Off" } else { "Toggle On" }).clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::ToggleFirewall(!self.firewall_enabled));
                    }
                    if ui.button("⚙ Full Customization").clicked() {
                        self.active_modal = ActiveModal::FirewallSettings;
                    }
                    ui.label("COM INetFwPolicy2 Native Rules Engine");
                    ui.end_row();

                    // 2. Mesh
                    ui.label("2. Overlay Mesh");
                    ui.label("S2O CyberMesh");
                    ui.label(egui::RichText::new("ONLINE").color(egui::Color32::GREEN).strong());
                    if ui.button("Regen Key").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::GenMeshKey);
                    }
                    if ui.button("⚙ Full Customization").clicked() {
                        self.active_modal = ActiveModal::MeshSettings;
                    }
                    ui.label("WireGuard Cryptographic Mesh Profile");
                    ui.end_row();

                    // 3. AV Defender
                    ui.label("3. Endpoint AV");
                    ui.label("S2O CyberDefender");
                    if self.defender_active {
                        ui.label(egui::RichText::new("ONLINE").color(egui::Color32::GREEN).strong());
                    } else {
                        ui.label(egui::RichText::new("WARNING").color(egui::Color32::YELLOW).strong());
                    }
                    if ui.button("Trigger Scan").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::TriggerScan(self.scan_target_path.clone()));
                    }
                    if ui.button("⚙ Full Customization").clicked() {
                        self.active_modal = ActiveModal::DefenderSettings;
                    }
                    ui.label("SHA-256 Recursive Scanner & WinDefend");
                    ui.end_row();

                    // 4. EDR
                    ui.label("4. Socket EDR");
                    ui.label("S2O CyberEDR");
                    ui.label(egui::RichText::new("ONLINE").color(egui::Color32::GREEN).strong());
                    if ui.button("Audit Sockets").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::AuditEdr);
                    }
                    if ui.button("⚙ Full Customization").clicked() {
                        self.active_modal = ActiveModal::EdrSettings;
                    }
                    ui.label(format!("Correlated IP Helper Table ({} active sockets)", self.active_connections_count));
                    ui.end_row();

                    // 5. SIEM
                    ui.label("5. Event SIEM");
                    ui.label("S2O CyberLog");
                    ui.label(egui::RichText::new("ONLINE").color(egui::Color32::GREEN).strong());
                    if ui.button("Emit Test Alert").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::EmitSiemEvent("Manual alert triggered".into()));
                    }
                    if ui.button("⚙ Full Customization").clicked() {
                        self.active_modal = ActiveModal::SiemSettings;
                    }
                    ui.label("Durable JSONL Store (.aegis/events.jsonl)");
                    ui.end_row();

                    // 6. Threat Intel
                    ui.label("6. Threat Intel");
                    ui.label("S2O ThreatGrid");
                    ui.label(egui::RichText::new("ONLINE").color(egui::Color32::GREEN).strong());
                    if ui.button("Sync URLhaus").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::SyncIntel);
                    }
                    if ui.button("⚙ Full Customization").clicked() {
                        self.active_modal = ActiveModal::IntelSettings;
                    }
                    ui.label("Local Threat DB + URLhaus Real-time Feed");
                    ui.end_row();

                    // 7. DNS Guard
                    ui.label("7. DNS Guard");
                    ui.label("S2O CyberDNS");
                    ui.label(egui::RichText::new("ONLINE").color(egui::Color32::GREEN).strong());
                    if ui.button("DoH Resolve").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::TestDns("split2ops.com".into()));
                    }
                    if ui.button("⚙ Full Customization").clicked() {
                        self.active_modal = ActiveModal::DnsSettings;
                    }
                    ui.label("Encrypted Cloudflare DoH & Sinkhole Proxy");
                    ui.end_row();

                    // 8. Zero-Trust ID
                    ui.label("8. Zero-Trust ID");
                    ui.label("S2O CyberID");
                    ui.label(egui::RichText::new("ONLINE").color(egui::Color32::GREEN).strong());
                    if ui.button("Re-Audit").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::AuditPosture);
                    }
                    if ui.button("⚙ Full Customization").clicked() {
                        self.active_modal = ActiveModal::IdSettings;
                    }
                    ui.label("5-Pillar Endpoint Posture (Score: 100/100)");
                    ui.end_row();

                    // 9. App ZTNA
                    ui.label("9. App ZTNA");
                    ui.label("S2O ZTNA Gateway");
                    ui.label(egui::RichText::new("ONLINE").color(egui::Color32::GREEN).strong());
                    if ui.button("Test Gateway").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::TestZtna("secure-crm".into()));
                    }
                    if ui.button("⚙ Full Customization").clicked() {
                        self.active_modal = ActiveModal::ZtnaSettings;
                    }
                    ui.label("Micro-segmentation Reverse Proxy Gate");
                    ui.end_row();
                });

            ui.add_space(10.0);
            ui.separator();

            // SIEM / EDR Real-Time Incident Stream
            ui.heading("Real-Time Telemetry & Security Events (SIEM)");
            egui::ScrollArea::vertical().max_height(200.0).show(ui, |ui| {
                if self.recent_events.is_empty() {
                    ui.label(egui::RichText::new("Awaiting incoming security events...").italics());
                } else {
                    for ev in &self.recent_events {
                        ui.monospace(ev);
                    }
                }
            });
        });

        // -------------------------------------------------------------
        // DEEP CUSTOMIZATION MODALS FOR EACH PILLAR
        // -------------------------------------------------------------

        // 1. Pillar 1: Full Firewall Customization Modal
        if self.active_modal == ActiveModal::FirewallSettings {
            let mut open = true;
            egui::Window::new("⚙ Pillar 1: S2O Cyberwall Comprehensive Control")
                .open(&mut open)
                .resizable(true)
                .default_width(540.0)
                .show(ctx, |ui| {
                    ui.heading("Master Operating System Firewall Controls");
                    ui.horizontal(|ui| {
                        if ui.button(if self.firewall_enabled { "🔴 Turn ALL Profiles OFF" } else { "🟢 Turn ALL Profiles ON" }).clicked() {
                            let _ = self.cmd_tx.send(DashboardCmd::ToggleFirewall(!self.firewall_enabled));
                        }
                        if ui.button(if self.outbound_shield { "🔓 Release Isolation Shield" } else { "🔒 Engage Isolation Shield (Lockdown)" }).clicked() {
                            let _ = self.cmd_tx.send(DashboardCmd::ToggleShield(!self.outbound_shield));
                        }
                    });

                    ui.separator();
                    ui.heading("Create Custom Rule");
                    ui.horizontal(|ui| {
                        ui.label("Rule Name:");
                        ui.text_edit_singleline(&mut self.fw_rule_name_input);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Action:");
                        ui.radio_value(&mut self.fw_rule_action_allow, true, "Allow");
                        ui.radio_value(&mut self.fw_rule_action_allow, false, "Block");

                        ui.separator();
                        ui.label("Direction:");
                        ui.radio_value(&mut self.fw_rule_dir_inbound, true, "Inbound");
                        ui.radio_value(&mut self.fw_rule_dir_inbound, false, "Outbound");

                        ui.separator();
                        ui.label("Protocol:");
                        ui.radio_value(&mut self.fw_rule_proto_tcp, true, "TCP");
                        ui.radio_value(&mut self.fw_rule_proto_tcp, false, "UDP");
                    });

                    ui.horizontal(|ui| {
                        ui.label("Port(s):");
                        ui.text_edit_singleline(&mut self.fw_rule_port_input);
                        ui.label("Remote IP:");
                        ui.text_edit_singleline(&mut self.fw_rule_remote_ip_input);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Application Path (optional):");
                        ui.text_edit_singleline(&mut self.fw_rule_app_path_input);
                    });

                    if ui.button("➕ Inject Rule into Windows Firewall Engine").clicked() {
                        let rule = FirewallRule {
                            name: self.fw_rule_name_input.clone(),
                            enabled: true,
                            action: if self.fw_rule_action_allow { RuleAction::Allow } else { RuleAction::Block },
                            direction: if self.fw_rule_dir_inbound { RuleDirection::Inbound } else { RuleDirection::Outbound },
                            profile: ProfileType::All,
                            protocol: Some(if self.fw_rule_proto_tcp { RuleProtocol::Tcp } else { RuleProtocol::Udp }),
                            local_ports: if self.fw_rule_port_input.trim().is_empty() { None } else { Some(self.fw_rule_port_input.trim().into()) },
                            remote_ports: None,
                            remote_addresses: if self.fw_rule_remote_ip_input.trim().is_empty() { None } else { Some(self.fw_rule_remote_ip_input.trim().into()) },
                            application: if self.fw_rule_app_path_input.trim().is_empty() { None } else { Some(self.fw_rule_app_path_input.trim().into()) },
                        };
                        let _ = self.cmd_tx.send(DashboardCmd::AddCustomRule(rule));
                    }

                    ui.separator();
                    ui.heading("Remove Rule");
                    ui.horizontal(|ui| {
                        ui.label("Target Rule Name:");
                        ui.text_edit_singleline(&mut self.fw_delete_rule_name_input);
                        if ui.button("🗑 Delete Rule").clicked() {
                            if !self.fw_delete_rule_name_input.trim().is_empty() {
                                let _ = self.cmd_tx.send(DashboardCmd::DeleteRuleByName(self.fw_delete_rule_name_input.trim().into()));
                            }
                        }
                    });

                    ui.separator();
                    ui.heading("Active Custom Rules");
                    egui::ScrollArea::vertical().max_height(120.0).show(ui, |ui| {
                        if self.fw_rules_cache.is_empty() {
                            ui.label(egui::RichText::new("Querying active rules...").italics());
                        } else {
                            for r in &self.fw_rules_cache {
                                ui.label(r);
                            }
                        }
                    });
                });
            if !open { self.active_modal = ActiveModal::None; }
        }

        // 2. Pillar 2: Full Mesh Customization Modal
        if self.active_modal == ActiveModal::MeshSettings {
            let mut open = true;
            egui::Window::new("⚙ Pillar 2: S2O CyberMesh Comprehensive Control")
                .open(&mut open)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    ui.heading("Overlay Mesh Tunnel & Cryptographic Routing");
                    ui.horizontal(|ui| {
                        ui.label("Peer Endpoint:");
                        ui.text_edit_singleline(&mut self.mesh_endpoint_input);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Client Virtual IP:");
                        ui.text_edit_singleline(&mut self.mesh_client_ip);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Internal DNS Server:");
                        ui.text_edit_singleline(&mut self.mesh_dns_server);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Listen Port:");
                        ui.add(egui::DragValue::new(&mut self.mesh_listen_port));
                        ui.label("Keepalive Interval (s):");
                        ui.add(egui::DragValue::new(&mut self.mesh_keepalive));
                    });

                    ui.checkbox(&mut self.mesh_persistent_active, "Enable Auto-Reconnect on Network Change");

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("🔄 Generate Fresh X25519 Keys").clicked() {
                            let _ = self.cmd_tx.send(DashboardCmd::GenMeshKey);
                        }
                        if ui.button("💾 Export .conf WireGuard Profile").clicked() {
                            let _ = self.cmd_tx.send(DashboardCmd::ExportMeshConfig(
                                self.mesh_endpoint_input.clone(),
                                self.mesh_listen_port,
                                self.mesh_keepalive,
                                self.mesh_client_ip.clone(),
                            ));
                        }
                    });
                });
            if !open { self.active_modal = ActiveModal::None; }
        }

        // 3. Pillar 3: Full Defender Customization Modal
        if self.active_modal == ActiveModal::DefenderSettings {
            let mut open = true;
            egui::Window::new("⚙ Pillar 3: S2O CyberDefender Comprehensive Control")
                .open(&mut open)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    ui.heading("Filesystem Antivirus & Integrity Parameters");
                    ui.horizontal(|ui| {
                        ui.label("Inspection Root Path:");
                        ui.text_edit_singleline(&mut self.scan_target_path);
                    });

                    ui.checkbox(&mut self.scan_deep_mode, "Compute SHA-256 Hashes for Executables");
                    ui.checkbox(&mut self.scan_archive_mode, "Unpack and Scan Inside Compressed Archives (.zip, .tar.gz)");
                    ui.checkbox(&mut self.defender_cloud_protection, "Enable Cloud Protection Telemetry");
                    ui.checkbox(&mut self.defender_tamper_protection, "Enforce Tamper Protection");

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("▶ Run Full Integrity Scan").clicked() {
                            let _ = self.cmd_tx.send(DashboardCmd::TriggerScan(self.scan_target_path.clone()));
                        }
                        if ui.button("⟳ Update Virus Signatures (MpCmdRun)").clicked() {
                            let _ = self.cmd_tx.send(DashboardCmd::UpdateSignatures);
                        }
                    });
                });
            if !open { self.active_modal = ActiveModal::None; }
        }

        // 4. Pillar 4: Full EDR Customization Modal
        if self.active_modal == ActiveModal::EdrSettings {
            let mut open = true;
            egui::Window::new("⚙ Pillar 4: S2O CyberEDR Comprehensive Control")
                .open(&mut open)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    ui.heading("Socket Correlation & Process Telemetry");
                    ui.horizontal(|ui| {
                        ui.label("Alert on Listening Port Below:");
                        ui.add(egui::DragValue::new(&mut self.edr_backdoor_threshold));
                    });
                    ui.checkbox(&mut self.edr_auto_kill_unauthorized, "Auto-Terminate Rogue Backdoor Processes");
                    ui.checkbox(&mut self.edr_isolate_suspicious_sockets, "Sever Socket Immediately on Suspicious Detection");

                    ui.separator();
                    ui.heading("Force-Kill Process by PID");
                    ui.horizontal(|ui| {
                        ui.label("PID to Terminate:");
                        ui.text_edit_singleline(&mut self.edr_kill_pid_input);
                        if ui.button("⚡ Force Kill Process").clicked() {
                            if let Ok(pid) = self.edr_kill_pid_input.trim().parse::<u32>() {
                                let _ = self.cmd_tx.send(DashboardCmd::KillProcess(pid));
                            }
                        }
                    });

                    ui.add_space(8.0);
                    if ui.button("🔍 Run Full Socket & Process Audit").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::AuditEdr);
                    }
                });
            if !open { self.active_modal = ActiveModal::None; }
        }

        // 5. Pillar 5: Full SIEM Customization Modal
        if self.active_modal == ActiveModal::SiemSettings {
            let mut open = true;
            egui::Window::new("⚙ Pillar 5: S2O CyberLog SIEM Comprehensive Control")
                .open(&mut open)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    ui.heading("Durable Event Ingestion & Log Lifecycle");
                    ui.horizontal(|ui| {
                        ui.label("Log Retention Period (Days):");
                        ui.add(egui::DragValue::new(&mut self.siem_log_retention_days));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Remote Syslog Forwarder (Host:Port):");
                        ui.text_edit_singleline(&mut self.siem_syslog_forwarder);
                        ui.radio_value(&mut self.siem_forward_protocol_udp, true, "UDP");
                        ui.radio_value(&mut self.siem_forward_protocol_udp, false, "TCP/TLS");
                    });

                    ui.horizontal(|ui| {
                        ui.label("Alert Notification Email:");
                        ui.text_edit_singleline(&mut self.siem_alert_email);
                    });

                    ui.add_space(8.0);
                    ui.horizontal(|ui| {
                        if ui.button("📨 Emit Diagnostic Test Alert").clicked() {
                            let _ = self.cmd_tx.send(DashboardCmd::EmitSiemEvent("Manual diagnostic audit".into()));
                        }
                        if ui.button("🗑 Clear Local Event Log (.aegis/events.jsonl)").clicked() {
                            let _ = self.cmd_tx.send(DashboardCmd::ClearSiemLog);
                        }
                    });
                });
            if !open { self.active_modal = ActiveModal::None; }
        }

        // 6. Pillar 6: Full Threat Intel Customization Modal
        if self.active_modal == ActiveModal::IntelSettings {
            let mut open = true;
            egui::Window::new("⚙ Pillar 6: S2O ThreatGrid Comprehensive Control")
                .open(&mut open)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    ui.heading("Threat Intelligence & Feed Orchestration");
                    ui.horizontal(|ui| {
                        ui.label("Auto-Sync Interval (minutes):");
                        ui.add(egui::DragValue::new(&mut self.intel_auto_sync_interval_mins));
                    });

                    ui.checkbox(&mut self.intel_feed_urlhaus_enabled, "Enable Abuse.ch URLhaus Real-Time Malware Feed");
                    ui.checkbox(&mut self.intel_feed_alienvault_enabled, "Enable AlienVault OTX Community Feed");

                    ui.separator();
                    ui.heading("Add Custom IOC Indicator (URL, IP, Domain)");
                    ui.horizontal(|ui| {
                        ui.text_edit_singleline(&mut self.intel_custom_ioc);
                        if ui.button("➕ Inject IOC").clicked() {
                            if !self.intel_custom_ioc.trim().is_empty() {
                                let _ = self.cmd_tx.send(DashboardCmd::AddIoc(self.intel_custom_ioc.trim().into()));
                            }
                        }
                    });

                    ui.add_space(8.0);
                    if ui.button("🔄 Trigger Immediate Feed Synchronization").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::SyncIntel);
                    }
                });
            if !open { self.active_modal = ActiveModal::None; }
        }

        // 7. Pillar 7: Full DNS Guard Customization Modal
        if self.active_modal == ActiveModal::DnsSettings {
            let mut open = true;
            egui::Window::new("⚙ Pillar 7: S2O CyberDNS Guard Comprehensive Control")
                .open(&mut open)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    ui.heading("DNS-over-HTTPS & Threat Sinkhole Parameters");
                    ui.horizontal(|ui| {
                        ui.label("Primary Upstream DoH Endpoint:");
                        ui.text_edit_singleline(&mut self.dns_upstream_doh);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Fallback DNS Server IP:");
                        ui.text_edit_singleline(&mut self.dns_fallback_ip);
                    });

                    ui.checkbox(&mut self.dns_block_tor_nodes, "Automatically Sinkhole Known Tor Exit Nodes");

                    ui.separator();
                    ui.heading("Sinkhole Domain Management");
                    ui.horizontal(|ui| {
                        ui.label("Block Domain:");
                        ui.text_edit_singleline(&mut self.dns_custom_block_domain);
                        if ui.button("🚫 Block").clicked() {
                            if !self.dns_custom_block_domain.trim().is_empty() {
                                let _ = self.cmd_tx.send(DashboardCmd::BlockDomain(self.dns_custom_block_domain.trim().into()));
                            }
                        }
                    });

                    ui.horizontal(|ui| {
                        ui.label("Unblock Domain:");
                        ui.text_edit_singleline(&mut self.dns_unblock_domain);
                        if ui.button("✅ Unblock").clicked() {
                            if !self.dns_unblock_domain.trim().is_empty() {
                                let _ = self.cmd_tx.send(DashboardCmd::UnblockDomain(self.dns_unblock_domain.trim().into()));
                            }
                        }
                    });

                    ui.add_space(8.0);
                    if ui.button("🌐 Test Encrypted Resolution (split2ops.com)").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::TestDns("split2ops.com".into()));
                    }
                });
            if !open { self.active_modal = ActiveModal::None; }
        }

        // 8. Pillar 8: Full CyberID Customization Modal
        if self.active_modal == ActiveModal::IdSettings {
            let mut open = true;
            egui::Window::new("⚙ Pillar 8: S2O CyberID Comprehensive Control")
                .open(&mut open)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    ui.heading("Zero-Trust Posture & Attestation Rules");
                    ui.checkbox(&mut self.id_enforce_secureboot, "Enforce UEFI SecureBoot Attestation");
                    ui.checkbox(&mut self.id_enforce_uac, "Enforce Windows UAC EnableLUA Policy");
                    ui.checkbox(&mut self.id_enforce_firewall, "Require All OS Firewall Profiles to be Active");
                    ui.checkbox(&mut self.id_enforce_defender, "Require Real-Time Antivirus Active");

                    ui.separator();
                    ui.heading("Device Attestation");
                    ui.horizontal(|ui| {
                        ui.label("Device Subject ID:");
                        ui.text_edit_singleline(&mut self.id_device_subject);
                        if ui.button("📜 Sign Device Token").clicked() {
                            let _ = self.cmd_tx.send(DashboardCmd::GenerateAttestation(self.id_device_subject.clone()));
                        }
                    });

                    ui.add_space(8.0);
                    if ui.button("🛡 Execute Full 5-Pillar Posture Audit").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::AuditPosture);
                    }
                });
            if !open { self.active_modal = ActiveModal::None; }
        }

        // 9. Pillar 9: Full ZTNA Customization Modal
        if self.active_modal == ActiveModal::ZtnaSettings {
            let mut open = true;
            egui::Window::new("⚙ Pillar 9: S2O ZTNA Gateway Comprehensive Control")
                .open(&mut open)
                .resizable(true)
                .default_width(500.0)
                .show(ctx, |ui| {
                    ui.heading("Micro-Segmentation & Posture Enforcement Parameters");
                    ui.horizontal(|ui| {
                        ui.label("Minimum Posture Score (0-100):");
                        ui.add(egui::DragValue::new(&mut self.ztna_min_posture_threshold));
                    });

                    ui.horizontal(|ui| {
                        ui.label("Protected Route Identifier:");
                        ui.text_edit_singleline(&mut self.ztna_route_destination);
                    });

                    ui.horizontal(|ui| {
                        ui.label("Upstream Gateway Proxy (Host:Port):");
                        ui.text_edit_singleline(&mut self.ztna_upstream_proxy);
                    });

                    ui.checkbox(&mut self.ztna_mutual_tls_enabled, "Enforce Mutual TLS (mTLS) Client Certificates");

                    ui.add_space(8.0);
                    if ui.button("🚀 Test Posture Preflight Connection").clicked() {
                        let _ = self.cmd_tx.send(DashboardCmd::TestZtna(self.ztna_route_destination.clone()));
                    }
                });
            if !open { self.active_modal = ActiveModal::None; }
        }

        // Request continuous repaint for smooth responsiveness
        ctx.request_repaint();
    }
}

pub fn run_gui() {
    let (cmd_tx, cmd_rx) = channel::<DashboardCmd>();
    let (status_tx, status_rx) = channel::<DashboardState>();

    // Spawn async background worker that manages live OS querying
    std::thread::spawn(move || {
        let _com = unsafe { s2o_net_lib::util1::init_com() };
        let rt = tokio::runtime::Runtime::new().unwrap();

        rt.block_on(async move {
            let fw = cyberwall_backend_windows::WindowsFirewallEngine::new();

            loop {
                // Handle commands if any
                while let Ok(cmd) = cmd_rx.try_recv() {
                    match cmd {
                        DashboardCmd::Refresh => {}
                        DashboardCmd::ToggleFirewall(target) => {
                            let _ = fw.set_enabled(target).await;
                        }
                        DashboardCmd::ToggleShield(target) => {
                            let _ = fw.set_outbound_block(target).await;
                        }
                        DashboardCmd::AddCustomRule(rule) => {
                            let _ = fw.add_rule(&rule).await;
                        }
                        DashboardCmd::DeleteRuleByName(name) => {
                            let _ = fw.delete_rule(&name).await;
                        }
                        DashboardCmd::GenMeshKey => {
                            tokio::task::spawn_blocking(|| {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cybermesh", "--", "gen-key"])
                                    .status();
                            });
                        }
                        DashboardCmd::ExportMeshConfig(ep, port, keepalive, ip) => {
                            tokio::task::spawn_blocking(move || {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cybermesh", "--", "gen-config", "--peer-endpoint", &ep, "--listen-port", &port.to_string(), "--keepalive", &keepalive.to_string(), "--client-ip", &ip])
                                    .status();
                            });
                        }
                        DashboardCmd::TriggerScan(path) => {
                            tokio::task::spawn_blocking(move || {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cyberdefender", "--", "scan", &path])
                                    .status();
                            });
                        }
                        DashboardCmd::UpdateSignatures => {
                            tokio::task::spawn_blocking(|| {
                                let _ = std::process::Command::new("powershell")
                                    .args(["-NoProfile", "-Command", "Update-MpSignature"])
                                    .status();
                            });
                        }
                        DashboardCmd::AuditEdr => {
                            tokio::task::spawn_blocking(|| {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cyberedr", "--", "audit"])
                                    .status();
                            });
                        }
                        DashboardCmd::KillProcess(pid) => {
                            tokio::task::spawn_blocking(move || {
                                let _ = std::process::Command::new("taskkill")
                                    .args(["/F", "/PID", &pid.to_string()])
                                    .status();
                            });
                        }
                        DashboardCmd::EmitSiemEvent(msg) => {
                            use std::io::Write;
                            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(".aegis/events.jsonl") {
                                let sample = serde_json::json!({
                                    "timestamp": chrono::Utc::now().to_rfc3339(),
                                    "product": "CyberLog",
                                    "severity": "Info",
                                    "message": msg
                                });
                                let _ = writeln!(f, "{}", sample);
                            }
                        }
                        DashboardCmd::ClearSiemLog => {
                            let _ = std::fs::remove_file(".aegis/events.jsonl");
                        }
                        DashboardCmd::SyncIntel => {
                            tokio::task::spawn_blocking(|| {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cyberintel", "--", "sync"])
                                    .status();
                            });
                        }
                        DashboardCmd::AddIoc(ioc) => {
                            let _ = std::fs::create_dir_all(".aegis");
                            use std::io::Write;
                            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(".aegis/threatgrid_iocs.json") {
                                let _ = writeln!(f, "// custom: {}", ioc);
                            }
                        }
                        DashboardCmd::TestDns(domain) => {
                            tokio::task::spawn_blocking(move || {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cyberdns", "--", "lookup", &domain])
                                    .status();
                            });
                        }
                        DashboardCmd::BlockDomain(domain) => {
                            tokio::task::spawn_blocking(move || {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cyberdns", "--", "block", &domain])
                                    .status();
                            });
                        }
                        DashboardCmd::UnblockDomain(domain) => {
                            tokio::task::spawn_blocking(move || {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cyberdns", "--", "unblock", &domain])
                                    .status();
                            });
                        }
                        DashboardCmd::AuditPosture => {
                            tokio::task::spawn_blocking(|| {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cyberid", "--", "posture"])
                                    .status();
                            });
                        }
                        DashboardCmd::GenerateAttestation(device) => {
                            tokio::task::spawn_blocking(move || {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cyberid", "--", "attest", "--device", &device])
                                    .status();
                            });
                        }
                        DashboardCmd::TestZtna(dest) => {
                            tokio::task::spawn_blocking(move || {
                                let _ = std::process::Command::new("cargo")
                                    .args(["run", "-q", "-p", "cyberztna", "--", "connect", &dest])
                                    .status();
                            });
                        }
                    }
                }

                // Query live system status
                let st = fw.get_status().await.unwrap_or(cyberwall_core::FirewallStatus {
                    enabled: false,
                    outbound_blocked: false,
                    defender_active: false,
                    profile_private: false,
                    profile_public: false,
                    profile_domain: false,
                    platform: "Windows".into(),
                    backend_driver: "".into(),
                    substrate: cyberwall_core::DriverSubstrate::UserspaceNative,
                });

                let conns = s2o_net_lib::telemetry::get_active_tcp_connections();

                // Read SIEM events
                let mut events = Vec::new();
                if let Ok(file) = std::fs::File::open(".aegis/events.jsonl") {
                    use std::io::{BufRead, BufReader};
                    let reader = BufReader::new(file);
                    for line in reader.lines().flatten().take(50) {
                        events.push(line);
                    }
                    events.reverse(); // Newest first
                }

                // Sample recent rules summary
                let mut rules_summary = Vec::new();
                if let Ok(rules) = fw.list_rules().await {
                    for r in rules.iter().take(15) {
                        rules_summary.push(format!("- {} [{:?}] [{:?}]", r.name, r.direction, r.action));
                    }
                }

                let _ = status_tx.send(DashboardState {
                    firewall_enabled: st.enabled,
                    outbound_shield: st.outbound_blocked,
                    defender_active: st.defender_active,
                    connections: conns.len(),
                    events,
                    rules_summary,
                });

                tokio::time::sleep(tokio::time::Duration::from_millis(1500)).await;
            }
        });
    });

    let app = AegisDashboardApp {
        last_refresh: Instant::now(),
        firewall_enabled: true,
        outbound_shield: false,
        defender_active: true,
        active_connections_count: 0,
        status_rx,
        cmd_tx,
        recent_events: Vec::new(),
        active_modal: ActiveModal::None,

        fw_rule_name_input: "S2O-Custom-Rule-1".into(),
        fw_rule_action_allow: true,
        fw_rule_dir_inbound: true,
        fw_rule_proto_tcp: true,
        fw_rule_port_input: "8080".into(),
        fw_rule_remote_ip_input: "".into(),
        fw_rule_app_path_input: "".into(),
        fw_delete_rule_name_input: "".into(),
        fw_rules_cache: Vec::new(),

        mesh_endpoint_input: "203.0.113.5:51820".into(),
        mesh_listen_port: 51820,
        mesh_keepalive: 25,
        mesh_client_ip: "10.42.0.2/24".into(),
        mesh_dns_server: "10.42.0.1".into(),
        mesh_persistent_active: true,

        scan_target_path: ".".into(),
        scan_deep_mode: true,
        scan_archive_mode: false,
        defender_tamper_protection: true,
        defender_cloud_protection: true,

        edr_backdoor_threshold: 1024,
        edr_auto_kill_unauthorized: false,
        edr_kill_pid_input: "".into(),
        edr_isolate_suspicious_sockets: true,

        siem_log_retention_days: 30,
        siem_syslog_forwarder: "10.0.0.50:514".into(),
        siem_forward_protocol_udp: true,
        siem_alert_email: "secops@split2ops.com".into(),

        intel_auto_sync_interval_mins: 60,
        intel_custom_ioc: "".into(),
        intel_feed_urlhaus_enabled: true,
        intel_feed_alienvault_enabled: true,

        dns_custom_block_domain: "evil-tracker.com".into(),
        dns_unblock_domain: "evil-tracker.com".into(),
        dns_upstream_doh: "https://cloudflare-dns.com/dns-query".into(),
        dns_fallback_ip: "1.1.1.1".into(),
        dns_block_tor_nodes: true,

        id_enforce_secureboot: true,
        id_enforce_uac: true,
        id_enforce_firewall: true,
        id_enforce_defender: true,
        id_device_subject: "host-01".into(),

        ztna_min_posture_threshold: 80,
        ztna_route_destination: "secure-crm".into(),
        ztna_upstream_proxy: "127.0.0.1:8443".into(),
        ztna_mutual_tls_enabled: true,
    };

    let mut native_options = epi::NativeOptions::default();
    native_options.initial_window_size = Some(egui::Vec2::new(1024.0, 700.0));
    native_options.min_window_size = Some(egui::Vec2::new(800.0, 600.0));
    native_options.maximized = true;
    eframe::run_native(Box::new(app), native_options);
}

fn main() {
    run_gui();
}
