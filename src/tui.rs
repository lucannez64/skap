use std::{io, str::FromStr, time::{Duration, SystemTime, UNIX_EPOCH}};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use data_encoding::BASE32_NOPAD;
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, ListState, Paragraph, Widget, Wrap},
    Frame, Terminal,
};
use uuid::Uuid;
use serde::{Serialize, Deserialize};
use crate::{client, protocol::{self, ClientEx, Password, ProtocolError}};
use cli_clipboard::{ClipboardContext, ClipboardProvider};
use ring::hmac;

#[derive(PartialEq)]
enum CurrentScreen {
    Main,
    AddingPassword,
    ViewingPasswords,
    EditingPassword,
    Exiting,
}

#[derive(Clone)]
struct StatefulList<T> {
    state: ListState,
    items: Vec<T>,
}

impl<T> StatefulList<T> {
    fn with_items(items: Vec<T>) -> Self {
        Self {
            state: ListState::default(),
            items,
        }
    }

    fn next(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.state.selected() {
            Some(i) => {
                if i == 0 {
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.state.select(Some(i));
    }
}

struct App {
    current_screen: CurrentScreen,
    email_input: String,
    password_list: StatefulList<(Password, Uuid)>,
    new_password: Password,
    edit_password: Password,
    error_message: Option<String>,
    client: Option<(crate::protocol::Client, crate::protocol::CK)>,
    logged_in: bool,
    current_field: usize,
    log_or_create: bool,
    entered_log: bool,
    editing_password_id: Option<Uuid>,
    ctx: Clipboard,
    importing: bool,
    importing_state: usize,
    importing_total: usize,
    searching: bool,
    search: String,
    filtered: StatefulList<(Password, Uuid)>,
}

#[cfg(not(target_os = "windows"))]
struct Clipboard {
    linux: Option<ClipboardContext>,
    windows: Option<u64>,
}

#[cfg(target_os = "windows")]
struct Clipboard {
    windows: Option<u64>,
    linux: Option<u64>,
}

impl Clipboard {
    #[cfg(not(target_os = "windows"))]
    fn set_contents(&self, contents: String) -> Result<(), String> {
        self.linux.unwrap().set_contents(contents).map_err(|e| e.to_string())?;
        Ok(())
    }

    #[cfg(target_os = "windows")]
    fn set_contents(&self, contents: String) -> Result<(), String> {
        use clipboard_win::{Clipboard, Setter};
        clipboard_win::set_clipboard_string(&contents).map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(not(target_os = "windows"))]
impl App {
    fn new() -> Self {
        Self {
            current_screen: CurrentScreen::Main,
            email_input: String::new(),
            password_list: StatefulList::with_items(Vec::new()),
            new_password: Password {
                username: String::new(),
                password: String::new(),
                app_id: None,
                description: None,
                url: Some(String::new()),
                otp: Some(String::new()),
            },
            edit_password: Password {
                username: String::new(),
                password: String::new(),
                app_id: None,
                description: None,
                url: Some(String::new()),
                otp: None,
            },
            error_message: None,
            client: None,
            logged_in: false,
            current_field: 0,
            log_or_create: false,
            entered_log: false,
            editing_password_id: None,
            ctx: Clipboard{linux: Some(ClipboardContext::new().unwrap()), windows: None},
            importing: false,
            importing_state: 0,
            importing_total: 0,
            searching: false,
            search: String::new(),
            filtered: StatefulList::with_items(Vec::new()),
        }
    }
}

#[cfg(target_os = "windows")]
impl App {
    fn new() -> Self {
        Self {
            current_screen: CurrentScreen::Main,
            email_input: String::new(),
            password_list: StatefulList::with_items(Vec::new()),
            new_password: Password {
                username: String::new(),
                password: String::new(),
                app_id: None,
                description: None,
                url: Some(String::new()),
                otp: Some(String::new()),
            },
            edit_password: Password {
                username: String::new(),
                password: String::new(),
                app_id: None,
                description: None,
                url: Some(String::new()),
                otp: None,
            },
            error_message: None,
            client: None,
            logged_in: false,
            current_field: 0,
            log_or_create: false,
            entered_log: false,
            editing_password_id: None,
            ctx: Clipboard{linux: None, windows: Some(0)},
            importing: false,
            importing_state: 0,
            importing_total: 0,
            searching: false,
            search: String::new(),
            filtered: StatefulList::with_items(Vec::new()),
        }
    }
}

pub async fn run_tui() -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let res = run_app(&mut terminal, &mut app).await;

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut App,
) -> io::Result<()> {
    let client = reqwest::Client::new();
    
    loop {
        terminal.draw(|f| ui(f, app))?;

        if let Ok(event) = event::poll(Duration::from_millis(100)) {
            if event {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        handle_input(key.code, app, &client).await;
                    }
                }
            }
        }

        if app.current_screen == CurrentScreen::Exiting {
            return Ok(());
        }
    }
}

async fn handle_input(key: KeyCode, app: &mut App, client: &reqwest::Client) {
    match app.current_screen {
        CurrentScreen::Main => handle_main_screen(key, app, client).await,
        CurrentScreen::AddingPassword => handle_add_screen(key, app, client).await,
        CurrentScreen::ViewingPasswords => handle_view_screen(key, app, client).await,
        CurrentScreen::EditingPassword => handle_edit_screen(key, app, client).await,
        CurrentScreen::Exiting => {}
    }
}

async fn handle_main_screen(key: KeyCode, app: &mut App, client2: &reqwest::Client) {
    match key {
        KeyCode::Enter => {
            if !app.logged_in {
                app.entered_log = true;
            } else {
                let passwords = jsonfile_to_vec(app.email_input.to_string()).unwrap();
                if let Some(client) = &mut app.client {
                    app.importing = true;
                    app.importing_total = passwords.len();
                    for password in passwords {
                        if let Ok(uuid) = client::create_pass(client2, client.1.id.unwrap(), &mut client.0, password.clone()).await {
                            app.password_list.items.push((password, uuid));
                            app.importing_state += 1;
                        }
                    }
                }
            }
        }
        KeyCode::Char('l') => {
            if app.entered_log {
                app.log_or_create = true;
                app.entered_log = false;
                match try_login(client2, &app.email_input).await {
                    Ok((client, ck)) => {
                        app.client = Some((client, ck));
                        app.logged_in = true;
                        app.error_message = None;
                    }
                    Err(e) => app.error_message = Some(format!("Login failed: {:?}", e)),
                }
            } else {
                app.email_input.push('l')
            }
        }
        KeyCode::Char('c') => {
            if app.entered_log {
                app.log_or_create = false;
                app.entered_log = false;
                match try_create(client2, &app.email_input).await {
                    Ok((client, ck)) => {
                        let a = ClientEx::new(&client, &ck);
                        a.to_file("client".to_string()).unwrap();
                        app.client = Some((client, ck));
                        app.logged_in = true;
                        app.error_message = None;
                    }
                    Err(e) => app.error_message = Some(format!("Login failed: {:?}", e)),
                }
            } else {
                app.email_input.push('c')
            }
        }
        KeyCode::Char('a') => {
            if app.logged_in {
                app.current_screen = CurrentScreen::AddingPassword;
                app.current_field = 0;
            } else {
                app.email_input.push('a')
            }
        }
        KeyCode::Char('v') => {
            if app.logged_in {
                if let Some(client) = &mut app.client {
                    if let Ok(passwords) = client::get_all(client2, client.1.id.unwrap(), &mut client.0).await {
                        app.password_list.items = passwords;
                        app.current_screen = CurrentScreen::ViewingPasswords;
                    }
                }
            } else {
                app.email_input.push('v')
            }
        }
        KeyCode::Esc => app.current_screen = CurrentScreen::Exiting,
        KeyCode::Char(c) => app.email_input.push(c),
        KeyCode::Backspace => {
            app.email_input.pop();
        }
        _ => {}
    }
}

async fn try_create(
    client2: &reqwest::Client,
    email: &str,
) -> Result<(crate::protocol::Client, protocol::CK), protocol::ProtocolError> {
    let (mut client, ck) = client::new(client2, email).await.map_err(|_| protocol::ProtocolError::AuthError)?;
    let uuid = ck.id.unwrap();
    client::auth(client2, uuid, &mut client).await.map_err(|_| protocol::ProtocolError::AuthError)?;
    Ok((client, ck))
}

async fn try_login(
    client2: &reqwest::Client,
    email: &str,
) -> Result<(crate::protocol::Client, protocol::CK), protocol::ProtocolError> {
    let c = ClientEx::from_file(email.to_string()).unwrap();
    let (mut client, ck) = (c.c, c.id);
    let uuid = ck.id.unwrap();
    client::auth(client2, uuid, &mut client).await.map_err(|_| protocol::ProtocolError::AuthError)?;
    Ok((client, ck))
}

async fn handle_add_screen(key: KeyCode, app: &mut App, client2: &reqwest::Client) {
    match key {
        KeyCode::Char(c) => {
            match app.current_field {
                0 => app.new_password.username.push(c),
                1 => app.new_password.password.push(c),
                2 => app.new_password.url.as_mut().unwrap().push(c),
                3 => app.new_password.otp.as_mut().unwrap().push(c),
                _ => {}
            }
        }
        KeyCode::Backspace => {
            match app.current_field {
                0 => app.new_password.username.pop(),
                1 => app.new_password.password.pop(),
                2 => app.new_password.url.as_mut().unwrap().pop(),
                3 => app.new_password.otp.as_mut().unwrap().pop(),
                _ => None,
            };
        }
        KeyCode::Down => {
            app.current_field = (app.current_field + 1) % 4;
        }
        KeyCode::Up => {
            app.current_field = (app.current_field - 1) % 4;
        }
        KeyCode::Enter => {
            if let Some(client) = &mut app.client {
                if let Ok(uuid) = client::create_pass(client2, client.1.id.unwrap(), &mut client.0, app.new_password.clone()).await {
                    app.password_list.items.push((app.new_password.clone(), uuid));
                    app.new_password.username.clear();
                    app.new_password.password.clear();
                    app.new_password.url.as_mut().unwrap().clear();
                    app.new_password.otp.as_mut().unwrap().clear();
                    app.current_screen = CurrentScreen::Main;
                } else {
                    app.error_message = Some("Failed to create password".to_string());
                }
            }
        }
        KeyCode::Esc => {
            app.current_screen = CurrentScreen::Main;
        }
        _ => {}
    }
}

async fn handle_view_screen(key: KeyCode, app: &mut App, client2: &reqwest::Client) {
    match key {
        KeyCode::Char('q') => { 
            if app.searching {
                app.search.push('q');
            } else {
                app.current_screen = CurrentScreen::Main
            }
        },
        KeyCode::Esc => {
            app.search = "".to_string();
            app.searching = false;
        }
        KeyCode::Down => {
            if app.search.is_empty() {
                app.password_list.next();
            } else {
                app.filtered.next();
            }
        },
        KeyCode::Up => {
            if app.search.is_empty() {
                app.password_list.previous();
            } else {
                app.filtered.previous();
            }
        },        
        KeyCode::Char('d') => {
            if let Some(selected) = app.password_list.state.selected() {
                let (_, uuid) = &app.password_list.items[selected];
                if let Some(client) = &mut app.client {
                    if client::delete_pass(client2, client.1.id.unwrap(), *uuid).await.is_ok() {
                        app.password_list.items.remove(selected);
                    } else {
                        app.error_message = Some("Failed to delete password".to_string());
                    }
                }
            } else if app.searching {
                app.search.push('d');
            }
        }
        KeyCode::Char('e') => {
            if let Some(selected) = app.password_list.state.selected() {
                let (pass, uuid) = &app.password_list.items[selected];
                app.edit_password = pass.clone();
                app.editing_password_id = Some(*uuid);
                app.current_screen = CurrentScreen::EditingPassword;
            } else if app.searching {
                app.search.push('e');
            }
        }
        KeyCode::Char('c') => {
            if let Some(selected) = app.password_list.state.selected() {
                let password = &app.password_list.items[selected].0.password;
                app.ctx.set_contents(password.to_string()).unwrap();    
            } else if app.searching {
                app.search.push('c');
            }
        }
        KeyCode::Char('o') => {
            if let Some(selected) = app.password_list.state.selected() {
                if app.password_list.items[selected].0.otp.is_some() {
                    let totp = otp(app.password_list.items[selected].0.otp.as_ref().unwrap());
                    app.ctx.set_contents(totp.generate().to_string()).unwrap();
                }

            } else if app.searching {
                app.search.push('o');
            }
        }
        KeyCode::Char('/') => {
            app.searching = true;
            app.search.clear();
        }
        KeyCode::Char(key) => {
            if app.searching {
                app.search.push(key);
            }
        }
        KeyCode::Enter => {
            if app.searching {
                app.searching = false; 
                app.filtered = StatefulList::with_items(app.password_list
            .items
            .iter()
            .filter(|(p, _)| p.username.contains(&app.search) || p.url.as_ref().unwrap_or(&"Unknown".to_string()).contains(&app.search))
            .cloned()
            .collect())
            }
        }
        KeyCode::Backspace => {
            if app.searching {
                app.search.pop();
            }
        }
        _ => {}
    }
}

async fn handle_edit_screen(key: KeyCode, app: &mut App, client2: &reqwest::Client) {
    match key {
        KeyCode::Char(c) => {
            match app.current_field {
                0 => app.edit_password.username.push(c),
                1 => app.edit_password.password.push(c),
                2 => app.edit_password.url.as_mut().unwrap().push(c),
                3 => app.edit_password.otp.as_mut().unwrap().push(c),
                _ => {}
            }
        }
        KeyCode::Backspace => {
            match app.current_field {
                0 => app.edit_password.username.pop(),
                1 => app.edit_password.password.pop(),
                2 => app.edit_password.url.as_mut().unwrap().pop(),
                3 => app.edit_password.otp.as_mut().unwrap().pop(),
                _ => None,
            };
        }
        KeyCode::Down => {
            app.current_field = (app.current_field + 1) % 4;
        }

        KeyCode::Up => {
            app.current_field = (app.current_field - 1) % 4;
        }
        KeyCode::Enter => {
            if let Some(client) = &mut app.client {
                if let Some(uuid) = app.editing_password_id {
                    if client::update_pass(client2, client.1.id.unwrap(), uuid, &mut client.0, app.edit_password.clone()).await.is_ok() {
                        if let Some(index) = app.password_list.items.iter().position(|(_, id)| *id == uuid) {
                            if app.edit_password.otp.is_some() && app.edit_password.otp == Some(String::new()) {
                                app.password_list.items[index].0.otp = None;
                            }
                            if app.edit_password.url.is_some() && app.edit_password.url == Some(String::new()) {
                                app.password_list.items[index].0.url = None;
                                
                            }
                            app.password_list.items[index].0 = app.edit_password.clone();
                        }
                        app.current_screen = CurrentScreen::ViewingPasswords;
                    } else {
                        app.error_message = Some("Failed to update password".to_string());
                    }
                }
            }
        }
        KeyCode::Esc => {
            app.current_screen = CurrentScreen::ViewingPasswords;
        }
        _ => {}
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(2),
                Constraint::Length(3),
            ]
            .as_ref(),
        )
        .split(f.area());

    match app.current_screen {
        CurrentScreen::Main => render_main_screen(f, app, chunks.to_vec()),
        CurrentScreen::AddingPassword => render_add_screen(f, app, chunks.to_vec()),
        CurrentScreen::ViewingPasswords => render_view_screen(f, app, chunks.to_vec()),
        CurrentScreen::EditingPassword => render_edit_screen(f, app, chunks.to_vec()),
        CurrentScreen::Exiting => {}
    }

    if let Some(error) = &app.error_message {
        let block = Paragraph::new(error.clone())
            .style(Style::default().fg(Color::Red))
            .block(Block::default().borders(Borders::ALL));
        f.render_widget(block, chunks[2]);
    }
}

fn render_main_screen(f: &mut Frame, app: &App, chunks: Vec<ratatui::layout::Rect>) {
    let email_input = Paragraph::new(app.email_input.as_str())
        .style(Style::default())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Email Address"),
        );

    let mut instructions = vec![
        Line::from(vec![
            Span::raw("Press "),
            Span::styled("enter", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" to login"),
        ]),
        Line::from(vec![
            Span::raw("Press "),
            Span::styled("a", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" to add new password"),
        ]),
        Line::from(vec![
            Span::raw("Press "),
            Span::styled("v", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" to view passwords"),
        ]),
        Line::from(vec![
            Span::raw("Press "),
            Span::styled("esc", Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" to exit"),
        ]),
    ];

    if app.logged_in {
        instructions.insert(0, Line::from(Span::styled(
            "Logged in successfully!",
            Style::default().fg(Color::Green),
        )));
    }

    let help_text = Paragraph::new(instructions)
        .block(Block::default().title("Help"))
        .wrap(Wrap { trim: true })
    ;
    if app.importing {
        let gauge = Gauge::default()
            .gauge_style(Style::default().fg(Color::Yellow))
            .ratio(app.importing_state as f64/app.importing_total as f64)
            .block(Block::default().title("Importing..."));
        f.render_widget(gauge, chunks[2]);
    }

    f.render_widget(email_input, chunks[0]);
    f.render_widget(help_text, chunks[1]);
}

fn render_add_screen(f: &mut Frame, app: &App, chunks: Vec<ratatui::layout::Rect>) {
    let fields = vec![
        Line::from(format!("Username: {}", app.new_password.username)),
        Line::from(format!("Password: {}", app.new_password.password)),
        Line::from(format!("URL: {}", app.new_password.url.as_ref().unwrap())),
        Line::from(format!("OTP: {}", app.new_password.otp.as_ref().unwrap())),
    ];

    let form = Paragraph::new(fields)
        .block(Block::default().borders(Borders::ALL).title("New Password"));
    
    let help_text = Paragraph::new(vec![
        Line::from("Navigate fields with UP and DOWN"),
        Line::from("Press ENTER to save"),
        Line::from("Press ESC to cancel"),
    ]);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(80),
            Constraint::Fill(1),
        ])
        .split(f.area());
    f.render_widget(form, chunks[0]);
    f.render_widget(help_text, chunks[1]);
}

fn render_view_screen(f: &mut Frame, app: &mut App, chunks: Vec<ratatui::layout::Rect>) {
    let mut wind = window::<(Password, Uuid)>(&app.password_list.items, app.password_list.state.selected().unwrap_or(0));
    if app.searching {
        app.filtered = StatefulList::with_items(app.password_list
            .items
            .iter()
            .filter(|(p, _)| {
                let search_text = format!("{} @ {}", p.username, p.url.as_ref().unwrap_or(&"Unknown".to_string()));
                search_text.contains(&app.search)
            })
            .cloned()
            .collect())
    }
    if app.search.is_empty() == false {

        wind = window::<(Password, Uuid)>(&app.filtered.items, app.filtered.state.selected().unwrap_or(0));
    }
    let mut statefu = StatefulList::with_items(wind.clone());
    statefu.state.select_first();
    let items: Vec<ListItem> = wind
        .iter()
        .map(|(pass, _z)| {
            let mut content = Line::from(format!(
                "{} @ {}",
                pass.username,
                pass.url.as_ref().unwrap_or(&"Unknown".to_string()),
            ));

            if pass.otp.is_some() {
                let totp = otp(pass.otp.as_ref().unwrap());
                content = Line::from(format!(
                    "{} @ {} - {}",
                    pass.username,
                    pass.url.as_ref().unwrap_or(&"Unknown".to_string()),
                    totp.generate().to_string(),
                ));

            }  

            ListItem::new(content)
        })
        .collect();

    let list = List::new(items)
        .block(Block::default().borders(Borders::ALL).title("Passwords"))
        .highlight_style(Style::default().add_modifier(Modifier::BOLD).fg(Color::LightCyan));
    let search_bar = Paragraph::new(app.search.as_str())
        .style(Style::default())
        .block(Block::default().borders(Borders::ALL).title("Search"));
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(80),
            Constraint::Length(3),
        ])
        .split(f.area());
    f.render_widget(search_bar,chunks[1]);

    f.render_stateful_widget(list, chunks[0], &mut statefu.state);
}

fn render_edit_screen(f: &mut Frame, app: &mut App, chunks: Vec<ratatui::layout::Rect>) {
    if app.edit_password.otp.is_none() {
        app.edit_password.otp = Some(String::new());
    }
    if app.edit_password.url.is_none() {
        app.edit_password.url = Some(String::new());
    }
    let fields = vec![
        Line::from(format!("Username: {}", app.edit_password.username)),
        Line::from(format!("Password: {}", app.edit_password.password)),
        Line::from(format!("URL: {}", app.edit_password.url.as_ref().unwrap())),
        Line::from(format!("OTP: {}", app.edit_password.otp.as_ref().unwrap_or(&"Unknown".to_string()))),
    ];

    let form = Paragraph::new(fields)
        .block(Block::default().borders(Borders::ALL).title("Edit Password"));
    
    let help_text = Paragraph::new(vec![
        Line::from("Navigate fields with UP and DOWN"),
        Line::from("Press ENTER to save"),
        Line::from("Press ESC to cancel"),
    ]);
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(80),
            Constraint::Fill(1),
        ])
        .split(f.area());
    f.render_widget(form, chunks[0]);
    f.render_widget(help_text, chunks[1]);
}


pub fn otp(uri: &str) -> TOTP {
    let totp = TOTP::from_uri(uri);
    totp
}

pub fn jsonfile_to_vec(filename: String) -> Result<Vec<Password>, io::Error> {
    // Read the JSON file into a string
    let data = std::fs::read_to_string(filename)?;

    // Parse the JSON string into a Vec<JsonPassword>
    let json_passwords: Vec<JsonPassword> = serde_json::from_str(&data)?;

    // Convert Vec<JsonPassword> to Vec<Password>
    let passwords = json_passwords
        .into_iter()
        .map(|json_password| Password {
            username: json_password.username,
            password: json_password.mdp,
            app_id: None, // You can modify this if needed
            description: None, // You can modify this if needed
            url: Some(json_password.name),
            otp: if json_password.otp.is_empty() {
                None
            } else {
                Some(json_password.otp)
            }
        })
        .collect();

    Ok(passwords)
}

#[derive(Serialize, Deserialize, Debug)]
struct JsonPassword {
    username: String,
    mdp: String,
    name: String,
    otp: String,
}


fn window<T: Clone>(v: &Vec<T>, selected: usize) -> Vec<T> {
    if selected < v.len() - 1 {

        let start = selected;
        let end = std::cmp::min(selected + 10, v.len());
        let window = &v[start..end];
        window.to_vec()
    } else {
        [].to_vec()
    }
}

pub struct TOTP {
    secret: String,
    digits: u8,
    period: u64,
    algorithm: String,
}

impl TOTP {
    fn from_uri(uri: &str) -> TOTP {
        let parsed_uri = url::Url::parse(uri).unwrap();
        let secret = parsed_uri
            .query_pairs()
            .find(|(k, _v)| k == "secret")
            .map(|(_k, v)| v.to_uppercase())
            .unwrap();

        let algorithm = parsed_uri
            .query_pairs()
            .find(|(k, _v)| k == "algorithm")
            .map_or_else(|| "SHA1".to_string(), |(_k, v)| v.to_uppercase());        
        let digits = parsed_uri
            .query_pairs()
            .find(|(k, _v)| k == "digits")
            .map_or(6, |(_k, v)| v.parse::<u8>().unwrap_or(6));
        let period = parsed_uri.query_pairs().find(|(k, _v)| k == "period").map_or(30, |(_k, v)| v.parse::<u64>().unwrap_or(30));     
        let totp = TOTP {
            secret,
            digits,
            period,
            algorithm,
        };
        totp
    }

    fn generate(&self) -> String {
        // Step 1: Get the current timestamp in seconds since the Unix epoch
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let decoded_secret = BASE32_NOPAD.decode(self.secret.to_uppercase().as_bytes()).unwrap();
        // Step 2: Calculate the counter value
        let counter = current_time / self.period;

        let message = counter.to_be_bytes();
        // Step 3: Generate the HMAC based on the algorithm
        let hmac_result = match self.algorithm.as_str() {
            "SHA1" => {
                let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &decoded_secret);
                let signature = hmac::sign(&key, &message);
                let sig_bytes = signature.as_ref();
                sig_bytes.to_vec()
            }
            "SHA256" => {
                let key = hmac::Key::new(hmac::HMAC_SHA256, &decoded_secret);
                let signature = hmac::sign(&key, &message);
                let sig_bytes = signature.as_ref();
                sig_bytes.to_vec()
            }
            "SHA512" => {
                let key = hmac::Key::new(hmac::HMAC_SHA512, &decoded_secret);
                let signature = hmac::sign(&key, &message);
                let sig_bytes = signature.as_ref();
                sig_bytes.to_vec()
            }
            _ => {
                let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &decoded_secret);
                let signature = hmac::sign(&key, &message);
                let sig_bytes = signature.as_ref();
                sig_bytes.to_vec()
            },
        };

        // Step 4: Dynamic truncation (DT) to extract a 31-bit integer
        let offset = (hmac_result[hmac_result.len() - 1] & 0x0F) as usize;
        let code_bytes = &hmac_result[offset..offset + 4];
        let code = u32::from_be_bytes([
            code_bytes[0] & 0x7F,
            code_bytes[1],
            code_bytes[2],
            code_bytes[3],
        ]) % 10u32.pow(self.digits.into());
        format!("{:0digits$}", code, digits = self.digits as usize) 
    }

}

