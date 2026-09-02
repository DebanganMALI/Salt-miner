#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui;
use saltminer_core::{Confidence, Verdict};
use std::sync::Arc;

const LOGO_PNG: &[u8] = include_bytes!("../assets/saltminer_256.png");

fn hex(c: u32) -> egui::Color32 {
    egui::Color32::from_rgb((c >> 16) as u8, (c >> 8) as u8, c as u8)
}

fn confidence_color(c: Confidence) -> egui::Color32 {
    match c {
        Confidence::High => hex(0x35C88A),
        Confidence::Medium => hex(0xE0AA3C),
        Confidence::Low => hex(0x8FA6B8),
    }
}

fn verdict_color(v: Verdict) -> egui::Color32 {
    match v {
        Verdict::Secure => hex(0x35C88A),
        Verdict::WeakParams => hex(0xE0AA3C),
        Verdict::Deprecated => hex(0xEF8A4A),
        Verdict::Broken => hex(0xEF6D5B),
    }
}

fn main() -> eframe::Result {
    let icon = eframe::icon_data::from_png_bytes(LOGO_PNG).expect("valid icon");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([560.0, 660.0])
            .with_min_inner_size([440.0, 500.0])
            .with_icon(Arc::new(icon)),
        ..Default::default()
    };
    eframe::run_native(
        "Saltminer",
        options,
        Box::new(|cc| Ok(Box::new(SaltminerApp::new(cc)))),
    )
}

struct SaltminerApp {
    input: String,
    logo: egui::TextureHandle,
}

impl SaltminerApp {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut v = egui::Visuals::dark();
        v.override_text_color = Some(hex(0xE0F6FC));
        v.panel_fill = hex(0x161E28);
        v.window_fill = hex(0x161E28);
        v.extreme_bg_color = hex(0x0F1620);
        v.widgets.inactive.bg_fill = hex(0x243647);
        v.widgets.hovered.bg_fill = hex(0x314A5E);
        v.selection.bg_fill = hex(0x2D6892);
        cc.egui_ctx.set_visuals(v);

        let img = image::load_from_memory(LOGO_PNG)
            .expect("decode logo")
            .to_rgba8();
        let (w, h) = img.dimensions();
        let color =
            egui::ColorImage::from_rgba_unmultiplied([w as usize, h as usize], img.as_raw());
        let logo = cc
            .egui_ctx
            .load_texture("logo", color, egui::TextureOptions::LINEAR);

        Self {
            input: String::new(),
            logo,
        }
    }
}

impl eframe::App for SaltminerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.add(egui::Image::new(egui::load::SizedTexture::new(
                    self.logo.id(),
                    egui::vec2(56.0, 56.0),
                )));
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.heading(
                        egui::RichText::new("Saltminer").size(26.0).color(hex(0x5AABD4)),
                    );
                    ui.label(
                        egui::RichText::new("Identify & audit password hashes — offline")
                            .color(hex(0x8FA6B8)),
                    );
                });
            });

            ui.add_space(12.0);
            ui.separator();
            ui.add_space(10.0);

            ui.label(egui::RichText::new("Paste a hash").color(hex(0x8FA6B8)));
            ui.add_space(4.0);
            ui.add(
                egui::TextEdit::singleline(&mut self.input)
                    .desired_width(f32::INFINITY)
                    .hint_text("e.g. 5f4dcc3b5aa765d61d8327deb882cf99"),
            );
            ui.add_space(14.0);

            let trimmed = self.input.trim().to_string();
            if trimmed.is_empty() {
                ui.label(
                    egui::RichText::new("Waiting for input…")
                        .italics()
                        .color(hex(0x515F6E)),
                );
                return;
            }

            let candidates = saltminer_core::identify(&trimmed);
            if candidates.is_empty() {
                ui.colored_label(hex(0xEF6D5B), "No identification possible.");
            } else {
                ui.label(
                    egui::RichText::new("Candidates").strong().color(hex(0x5AABD4)),
                );
                ui.add_space(6.0);
                for c in &candidates {
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new(&c.algorithm).strong());
                        ui.colored_label(
                            confidence_color(c.confidence),
                            format!("{:?}", c.confidence).to_lowercase(),
                        );
                        ui.label(egui::RichText::new(&c.reason).color(hex(0x8FA6B8)));
                    });
                }
            }

            ui.add_space(14.0);

            if let Some(report) = saltminer_core::audit(&trimmed) {
                ui.label(
                    egui::RichText::new("Security audit").strong().color(hex(0x5AABD4)),
                );
                ui.add_space(6.0);
                ui.colored_label(
                    verdict_color(report.verdict),
                    format!("{:?} — {}", report.verdict, report.algorithm),
                );
                ui.label(egui::RichText::new(&report.detail).color(hex(0x8FA6B8)));
            }
        });
    }
}
