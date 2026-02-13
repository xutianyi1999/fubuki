use crate::common::{format_elapsed, format_loss_percent, utc_to_str};
use crate::node::info_tui::Page::SelectedGroup;
use crate::node::InterfaceInfo;
use anyhow::anyhow;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use futures_util::StreamExt;
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use ratatui::layout::{Constraint, Layout, Margin};
use ratatui::style::{Color, Modifier, Style};
use ratatui::widgets::{Block, BorderType, Cell, Paragraph, Row, Table};
use ratatui::{DefaultTerminal, Frame};
use std::io;
use std::ops::Deref;
use tokio::net::TcpStream;

/// TUI theme: cyan accent, subtle borders, clear highlight
const BORDER: Style = Style::new().fg(Color::Cyan);
const TITLE: Style = Style::new().fg(Color::Cyan).add_modifier(Modifier::BOLD);
const HIGHLIGHT: Style = Style::new().fg(Color::Black).bg(Color::Cyan);
const MUTED: Style = Style::new().fg(Color::DarkGray);

#[derive(Copy, Clone)]
enum Page {
    Groups,
    SelectedGroup {
        select: usize
    },
    Interface,
    PeerNode {
        select: usize
    }
}

pub struct App {
    group_index: usize,
    page: Page,
    exit: bool,
    interfaces_info: Vec<InterfaceInfo>,
    event_stream: EventStream,
    api_addr: String,
}

impl App {
    pub fn new(api_addr: String) -> Self {
        Self {
            group_index: 0,
            page: Page::Groups,
            exit: false,
            interfaces_info: Vec::new(),
            event_stream: EventStream::new(),
            api_addr
        }
    }

    fn draw(&self, frame: &mut Frame) {
        let area = frame.area().inner(Margin { vertical: 1, horizontal: 2 });

        if self.interfaces_info.is_empty() {
            let layout = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
            let title = Paragraph::new(" Fubuki Node ")
                .style(TITLE)
                .block(Block::bordered().border_type(BorderType::Rounded).borders(ratatui::widgets::Borders::BOTTOM).border_style(BORDER));
            frame.render_widget(title, layout[0]);
            let msg = Paragraph::new(" No groups. Waiting for data… ")
                .style(MUTED)
                .block(Block::bordered().border_type(BorderType::Rounded).border_style(BORDER));
            frame.render_widget(msg, layout[1]);
            return;
        }

        match self.page {
            Page::Groups => {
                let layout = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
                let title = Paragraph::new(" Fubuki Node  │  ↑/↓ select  Enter open  q quit ")
                    .style(TITLE)
                    .block(Block::bordered().border_type(BorderType::Rounded).borders(ratatui::widgets::Borders::BOTTOM).border_style(BORDER));
                frame.render_widget(title, layout[0]);

                let header = Row::new(vec!["Group", "Node", "Local IP", "Peers"])
                    .style(Style::new().add_modifier(Modifier::BOLD))
                    .bottom_margin(1);
                let rows: Vec<Row> = self.interfaces_info
                    .iter()
                    .enumerate()
                    .map(|(idx, i)| {
                        let cells = vec![
                            Cell::from(i.group_name.as_deref().unwrap_or("—")),
                            Cell::from(i.node_name.as_str()),
                            Cell::from(i.addr.to_string()),
                            Cell::from(i.node_map.len().to_string()),
                        ];
                        Row::new(cells).style(if idx == self.group_index { HIGHLIGHT } else { Style::new() })
                    })
                    .collect();
                let widths = [Constraint::Min(12), Constraint::Min(10), Constraint::Min(14), Constraint::Length(6)];
                let table = Table::new(rows, widths)
                    .header(header)
                    .column_spacing(2)
                    .block(Block::bordered().border_type(BorderType::Rounded).title(" Groups ").border_style(BORDER));
                frame.render_widget(table, layout[1]);
            }
            Page::SelectedGroup { select } => {
                let interface = &self.interfaces_info[self.group_index];
                let mut nodes = interface.node_map.values().collect::<Vec<_>>();
                nodes.sort_unstable_by_key(|n| n.node.virtual_addr);

                let layout = Layout::vertical([Constraint::Length(3), Constraint::Length(5), Constraint::Fill(1)]).split(area);
                let title = Paragraph::new(" Fubuki Node  │  ↑/↓ select  Enter open  Esc back  q quit ")
                    .style(TITLE)
                    .block(Block::bordered().border_type(BorderType::Rounded).borders(ratatui::widgets::Borders::BOTTOM).border_style(BORDER));
                frame.render_widget(title, layout[0]);

                let header = Row::new(vec!["Group", "Node", "Local IP"]).style(Style::new().add_modifier(Modifier::BOLD)).bottom_margin(1);
                let interface_row = Row::new(vec![
                    Cell::from(interface.group_name.as_deref().unwrap_or("—")),
                    Cell::from(interface.node_name.as_str()),
                    Cell::from(interface.addr.to_string()),
                ]).style(if select == 0 { HIGHLIGHT } else { Style::new() });
                let block = Block::bordered().border_type(BorderType::Rounded).title(" Interface (row 0) ").border_style(BORDER);
                let t = Table::new([interface_row], [Constraint::Min(12), Constraint::Min(10), Constraint::Fill(1)]).header(header).column_spacing(2).block(block);
                frame.render_widget(t, layout[1]);

                let header2 = Row::new(vec!["Name", "Virtual IP", "Registered"]).style(Style::new().add_modifier(Modifier::BOLD)).bottom_margin(1);
                let peer_rows: Vec<Row> = nodes.iter().enumerate().map(|(idx, p)| {
                    let reg = utc_to_str(p.node.register_time).unwrap_or_else(|_| "—".to_string());
                    let style = if idx + 1 == select { HIGHLIGHT } else { Style::new() };
                    Row::new(vec![
                        Cell::from(p.node.name.as_str()),
                        Cell::from(p.node.virtual_addr.to_string()),
                        Cell::from(reg),
                    ]).style(style)
                }).collect();
                let widths2 = [Constraint::Min(10), Constraint::Min(14), Constraint::Min(20)];
                let t2 = Table::new(peer_rows, widths2)
                    .header(header2)
                    .column_spacing(2)
                    .block(Block::bordered().border_type(BorderType::Rounded).title(" Peers ").border_style(BORDER));
                frame.render_widget(t2, layout[2]);
            }
            Page::Interface => {
                let info = &self.interfaces_info[self.group_index];
                let layout = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
                let title = Paragraph::new(" Fubuki Node  │  Esc back  q quit ")
                    .style(TITLE)
                    .block(Block::bordered().border_type(BorderType::Rounded).borders(ratatui::widgets::Borders::BOTTOM).border_style(BORDER));
                frame.render_widget(title, layout[0]);

                let kvs = vec![
                    Row::new(vec![Cell::from("Index").style(MUTED), Cell::from(info.index.to_string())]),
                    Row::new(vec![Cell::from("Name").style(MUTED), Cell::from(info.node_name.as_str())]),
                    Row::new(vec![Cell::from("Group").style(MUTED), Cell::from(info.group_name.as_deref().unwrap_or("—"))]),
                    Row::new(vec![Cell::from("Local IP").style(MUTED), Cell::from(info.addr.to_string())]),
                    Row::new(vec![Cell::from("CIDR").style(MUTED), Cell::from(info.cidr.to_string())]),
                    Row::new(vec![Cell::from("Server address").style(MUTED), Cell::from(info.server_addr.as_str())]),
                    Row::new(vec![Cell::from("Mode").style(MUTED), Cell::from(format!("{:?}", info.mode))]),
                    Row::new(vec![Cell::from("Connected").style(MUTED), Cell::from(if info.server_is_connected { "Yes" } else { "No" })]),
                    Row::new(vec![Cell::from("UDP status").style(MUTED), Cell::from(info.server_udp_status.to_string())]),
                    Row::new(vec![Cell::from("UDP latency").style(MUTED), Cell::from(format_elapsed(info.server_udp_hc.elapsed.as_ref()))]),
                    Row::new(vec![Cell::from("UDP loss").style(MUTED), Cell::from(format_loss_percent(info.server_udp_hc.packet_loss_count, info.server_udp_hc.send_count))]),
                    Row::new(vec![Cell::from("TCP latency").style(MUTED), Cell::from(format_elapsed(info.server_tcp_hc.elapsed.as_ref()))]),
                    Row::new(vec![Cell::from("TCP loss").style(MUTED), Cell::from(format_loss_percent(info.server_tcp_hc.packet_loss_count, info.server_tcp_hc.send_count))]),
                ];
                let t = Table::new(kvs, [Constraint::Length(16), Constraint::Fill(1)])
                    .column_spacing(2)
                    .block(Block::bordered().border_type(BorderType::Rounded).title(" Interface ").border_style(BORDER));
                frame.render_widget(t, layout[1]);
            }
            Page::PeerNode { select } => {
                let interface = &self.interfaces_info[self.group_index];
                let mut nodes = interface.node_map.values().collect::<Vec<_>>();
                nodes.sort_unstable_by_key(|n| n.node.virtual_addr);
                let node = nodes[select];

                let layout = Layout::vertical([Constraint::Length(3), Constraint::Fill(1)]).split(area);
                let title = Paragraph::new(" Fubuki Node  │  Esc back  q quit ")
                    .style(TITLE)
                    .block(Block::bordered().border_type(BorderType::Rounded).borders(ratatui::widgets::Borders::BOTTOM).border_style(BORDER));
                frame.render_widget(title, layout[0]);

                let reg = utc_to_str(node.node.register_time).unwrap_or_else(|_| "—".to_string());
                let allowed_ips: String = node.node.allowed_ips.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ");
                let allowed_ips = if allowed_ips.is_empty() { "—".to_string() } else { allowed_ips };
                let lan_addr = node.node.lan_udp_addr.as_ref().map(ToString::to_string).unwrap_or_else(|| "—".to_string());
                let wan_addr = node.node.wan_udp_addr.as_ref().map(ToString::to_string).unwrap_or_else(|| "—".to_string());

                let kvs = vec![
                    Row::new(vec![Cell::from("Name").style(MUTED), Cell::from(node.node.name.as_str())]),
                    Row::new(vec![Cell::from("Virtual IP").style(MUTED), Cell::from(node.node.virtual_addr.to_string())]),
                    Row::new(vec![Cell::from("LAN address").style(MUTED), Cell::from(lan_addr)]),
                    Row::new(vec![Cell::from("WAN address").style(MUTED), Cell::from(wan_addr)]),
                    Row::new(vec![Cell::from("Mode").style(MUTED), Cell::from(format!("{:?}", node.node.mode))]),
                    Row::new(vec![Cell::from("Allowed IPs").style(MUTED), Cell::from(allowed_ips)]),
                    Row::new(vec![Cell::from("Registered").style(MUTED), Cell::from(reg)]),
                    Row::new(vec![Cell::from("UDP status").style(MUTED), Cell::from(node.udp_status.to_string())]),
                    Row::new(vec![Cell::from("Latency").style(MUTED), Cell::from(format_elapsed(node.hc.elapsed.as_ref()))]),
                    Row::new(vec![Cell::from("Loss").style(MUTED), Cell::from(format_loss_percent(node.hc.packet_loss_count, node.hc.send_count))]),
                ];
                let t = Table::new(kvs, [Constraint::Length(14), Constraint::Fill(1)])
                    .column_spacing(2)
                    .block(Block::bordered().border_type(BorderType::Rounded).title(" Peer ").border_style(BORDER));
                frame.render_widget(t, layout[1]);
            }
        }
    }

    fn handle_event(&mut self, event: Event) {
        let key_event = match event {
            Event::Key(e) => e,
            _ => return,
        };

        if key_event.kind != KeyEventKind::Press {
            return;
        }

        match &mut self.page {
            Page::Groups => {
                match key_event.code {
                    KeyCode::Esc | KeyCode::Char('q') => self.exit = true,
                    KeyCode::Up | KeyCode::Char('k') => {
                        self.group_index = self.group_index.saturating_sub(1);
                    } ,
                    KeyCode::Down | KeyCode::Char('j') => {
                        self.group_index = std::cmp::min(self.group_index + 1, self.interfaces_info.len() - 1);
                    },
                    KeyCode::Enter => {
                        self.page = Page::SelectedGroup {
                            select: 0
                        };
                    }
                    _ => {}
                }
            }
            Page::SelectedGroup { select } => {
                match key_event.code {
                    KeyCode::Esc | KeyCode::Char('q') => self.page = Page::Groups,
                    KeyCode::Up | KeyCode::Char('k') => {
                        *select = select.saturating_sub(1);
                    } ,
                    KeyCode::Down | KeyCode::Char('j') => {
                        *select = std::cmp::min(*select + 1, (self.interfaces_info[self.group_index].node_map.len() - 1) + 1);
                    },
                    KeyCode::Enter => {
                        if *select == 0 {
                            self.page = Page::Interface;
                        } else {
                            self.page = Page::PeerNode { select : *select - 1};
                        }
                    }
                    _ => {}
                }
            }
            Page::Interface => {
                match key_event.code {
                    KeyCode::Esc | KeyCode::Char('q') => self.page = Page::SelectedGroup { select: 0 },
                    _ => {}
                }
            }
            Page::PeerNode { select } => {
                match key_event.code {
                    KeyCode::Esc | KeyCode::Char('q') => self.page = Page::SelectedGroup { select: *select + 1 },
                    _ => {}
                }
            }
        }
    }

    async fn fetch_interfaces_info(&mut self) -> anyhow::Result<()> {
        let api_addr = &self.api_addr;

        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{}/info", api_addr))
            .body(Empty::<hyper::body::Bytes>::new())?;

        let stream = TcpStream::connect(api_addr).await?;
        let stream = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await?;

        tokio::spawn(conn);

        let resp = sender.send_request(req).await?;
        let (parts, body) = resp.into_parts();
        let bytes = body.collect().await?.to_bytes();

        if parts.status != 200 {
            let msg = std::str::from_utf8(&bytes)?;
            return Err(anyhow!("http response code: {}, message: {}", parts.status.as_u16(), msg));
        }

        let mut interfaces_info: Vec<InterfaceInfo> = serde_json::from_slice(bytes.deref())?;
        interfaces_info.sort_unstable_by_key(|v| v.index);
        self.interfaces_info = interfaces_info;
        Ok(())
    }

    fn prevent_idx_out_of_bounds(&mut self) {
        if self.interfaces_info.is_empty() {
            return;
        }
        self.group_index = std::cmp::min(self.group_index, self.interfaces_info.len() - 1);
        let node_count = self.interfaces_info[self.group_index].node_map.len();
        match &mut self.page {
            Page::Groups => {}
            Page::SelectedGroup { select } => {
                *select = std::cmp::min(*select, node_count);
            }
            Page::Interface => {}
            Page::PeerNode { select } => {
                if *select >= node_count {
                    self.page = SelectedGroup { select: node_count };
                }
            }
        }
    }

    pub async fn run(&mut self, terminal: &mut DefaultTerminal) -> anyhow::Result<()> {
        self.fetch_interfaces_info().await?;
        let mut iv = tokio::time::interval(tokio::time::Duration::from_secs(3));

        while !self.exit {
            tokio::select! {
                _ = iv.tick() => {
                    self.fetch_interfaces_info().await?;
                }
                res = self.event_stream.next() => {
                    let event = res.ok_or_else(|| io::Error::from(io::ErrorKind::Interrupted))??;
                    self.handle_event(event);
                }
            }

            self.prevent_idx_out_of_bounds();
            terminal.draw(|frame| self.draw(frame))?;
        }

        Ok(())
    }
}