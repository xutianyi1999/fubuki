use crate::common::utc_to_str;
use crate::server::GroupInfo;
use anyhow::anyhow;
use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use crossterm::style::Color;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use http_body_util::Empty;
use hyper::{Method, Request};
use hyper_util::rt::TokioIo;
use prettytable::format::consts::FORMAT_NO_BORDER_LINE_SEPARATOR;
use prettytable::{row, Table};
use ratatui::layout::Constraint::{Fill, Length};
use ratatui::layout::Layout;
use ratatui::prelude::{Line, Stylize};
use ratatui::widgets::Paragraph;
use ratatui::{DefaultTerminal, Frame};
use std::io;
use std::ops::Deref;
use tokio::net::TcpStream;

#[derive(Copy, Clone)]
enum Page {
    Groups,
    SelectedGroup {
        select: usize
    },
    Node {
        select: usize
    }
}

pub struct App {
    group_index: usize,
    page: Page,
    exit: bool,
    groups_info: Vec<GroupInfo>,
    event_stream: EventStream,
    api_addr: String,
}

impl App {
    pub fn new(api_addr: String) -> Self {
        Self {
            group_index: 0,
            page: Page::Groups,
            exit: false,
            groups_info: Vec::new(),
            event_stream: EventStream::new(),
            api_addr
        }
    }

    fn draw(&self, frame: &mut Frame) {
        let mut table_format = *FORMAT_NO_BORDER_LINE_SEPARATOR;
        table_format.left_border('[');
        table_format.right_border(']');

        let layout = Layout::vertical([Length(2), Fill(1)]);
        let [title_area, main_area] = layout.areas(frame.area());

        let title = Line::from("Fubuki Server").bold();
        frame.render_widget(title, title_area);

        match self.page {
            Page::Groups => {
                let mut table = Table::new();
                table.set_format(table_format);

                let mut table_lines = vec![Line::from("Groups")];

                for group_info in &self.groups_info {
                    let row = row![
                        &group_info.name,
                        group_info.listen_addr,
                        group_info.address_range
                    ];
                    table.add_row(row);
                }

                let table_str = table.to_string();
                for (idx, line) in table_str.lines().enumerate() {
                    let mut line = Line::from(line);

                    if self.group_index == idx {
                        line = line.black().bg(Color::White);
                    }

                    table_lines.push(line);
                }

                let groups = Paragraph::new(table_lines);
                frame.render_widget(groups, main_area);
            }
            Page::SelectedGroup { select } => {
                let group = &self.groups_info[self.group_index];

                let mut lines = vec![Line::from("Nodes")];
                let mut table = Table::new();
                table.set_format(table_format);

                let mut nodes = group.node_map.values().collect::<Vec<_>>();
                nodes.sort_unstable_by_key(|n| n.node.virtual_addr);

                for node in nodes {
                    let register_time = utc_to_str(node.node.register_time).unwrap();

                    table.add_row(row![
                        node.node.name,
                        node.node.virtual_addr,
                        register_time,
                    ]);
                }

                let table_str = table.to_string();

                for (idx, line) in table_str.lines().enumerate() {
                    let mut line = Line::from(line);

                    if select == idx {
                        line = line.black().bg(Color::White);
                    }

                    lines.push(line);
                }

                let lines = Paragraph::new(lines);
                frame.render_widget(lines, main_area);
            }
            Page::Node { select } => {
                let group = &self.groups_info[self.group_index];
                let mut nodes = group.node_map.values().collect::<Vec<_>>();
                nodes.sort_unstable_by_key(|n| n.node.virtual_addr);
                let node = nodes[select];

                let mut table = Table::new();
                table.set_format(table_format);

                let register_time = utc_to_str(node.node.register_time).unwrap();

                table.add_row(row!["NAME", node.node.name]);
                table.add_row(row!["IP", node.node.virtual_addr]);
                table.add_row(row!["LAN_ADDRESS", format!("{:?}", node.node.lan_udp_addr)]);
                table.add_row(row!["WAN_ADDRESS", format!("{:?}", node.node.wan_udp_addr)]);
                table.add_row(row!["PROTOCOL_MODE",  format!("{:?}", node.node.mode)]);
                table.add_row(row!["ALLOWED_IPS",  format!("{:?}", node.node.allowed_ips)]);
                table.add_row(row!["REGISTER_TIME", register_time]);
                table.add_row(row!["UDP_STATUS", node.udp_status]);
                table.add_row(row!["UDP_LATENCY", format!("{:?}", node.udp_heartbeat_cache.elapsed)]);

                let udp_loss_rate = node.udp_heartbeat_cache.packet_loss_count as f32 / node.udp_heartbeat_cache.send_count as f32 * 100f32;
                table.add_row(row!["UDP_LOSS_RATE", ternary!(!udp_loss_rate.is_nan(), format!("{}%", udp_loss_rate), String::new())]);

                table.add_row(row!["TCP_LATENCY", format!("{:?}", node.tcp_heartbeat_cache.elapsed)]);

                let tcp_loss_rate = node.tcp_heartbeat_cache.packet_loss_count as f32 / node.tcp_heartbeat_cache.send_count as f32 * 100f32;
                table.add_row(row!["TCP_LOSS_RATE", ternary!(!tcp_loss_rate.is_nan(), format!("{}%", tcp_loss_rate), String::new())]);

                let table = table.to_string();

                let mut lines = vec![Line::from("Node Status")];

                for line in table.lines() {
                    lines.push(Line::from(line));
                }

                frame.render_widget(Paragraph::new(lines), main_area);
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
                        self.group_index = std::cmp::min(self.group_index + 1, self.groups_info.len() - 1);
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
                        *select = std::cmp::min(*select + 1, self.groups_info[self.group_index].node_map.len() - 1);
                    },
                    KeyCode::Enter => {
                        self.page = Page::Node { select: *select}
                    }
                    _ => {}
                }
            }
            Page::Node { select } => {
                match key_event.code {
                    KeyCode::Esc | KeyCode::Char('q') => self.page = Page::SelectedGroup { select: *select },
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
            let msg = String::from_utf8(bytes.to_vec())?;
            return Err(anyhow!("http response code: {}, message: {}", parts.status.as_u16(), msg));
        }

        let groups: Vec<GroupInfo> = serde_json::from_slice(bytes.deref())?;
        self.groups_info = groups;
        Ok(())
    }

    fn prevent_idx_out_of_bounds(&mut self) {
        self.group_index = std::cmp::min(self.group_index, self.groups_info.len() - 1);
        match &mut self.page {
            Page::Groups => {}
            Page::SelectedGroup { select } => {
                *select = std::cmp::min(*select, self.groups_info[self.group_index].node_map.len() - 1);
            }
            Page::Node { select } => {
                if *select >= self.groups_info[self.group_index].node_map.len() {
                    self.page = Page::SelectedGroup { select: self.groups_info[self.group_index].node_map.len() - 1 }
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