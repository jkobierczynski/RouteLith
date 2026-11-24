//! `routelith ctl user`: add, change and remove the web UI's users (doc
//! §21.5 F11). The server notices changes to the users file by itself.

use std::io::BufRead;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Args, Subcommand};
use rl_core::config;
use rl_web::users::{MIN_PASSWORD, Role, User, Users, check_name, hash_password};

#[derive(Debug, Args)]
pub(crate) struct Where {
    /// Configuration file, for its users_file (default: users.toml in the
    /// data directory).
    #[arg(short, long, global = true)]
    config: Option<PathBuf>,
    /// The users file itself, instead of --config.
    #[arg(long, global = true)]
    users_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub(crate) enum UserAction {
    /// Add a user; asks for the password twice.
    Add {
        name: String,
        /// viewer (reads), operator (also silences alerts) or admin.
        #[arg(long, default_value = "viewer")]
        role: String,
        /// Read the password from the first line of standard input
        /// instead of asking.
        #[arg(long)]
        password_stdin: bool,
    },
    /// Set a user's password; asks for it twice.
    Passwd {
        name: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Change a user's role.
    Role { name: String, role: String },
    /// Remove a user; their sessions end at once.
    Remove { name: String },
    /// List the users and their roles.
    List,
}

#[derive(Debug, Args)]
pub(crate) struct UserArgs {
    #[command(subcommand)]
    action: UserAction,
    #[command(flatten)]
    at: Where,
}

pub(crate) fn run(args: UserArgs) -> ExitCode {
    match user(args) {
        Ok(msg) => {
            println!("{msg}");
            ExitCode::SUCCESS
        }
        Err((code, msg)) => {
            eprintln!("routelith ctl user: {msg}");
            ExitCode::from(code)
        }
    }
}

type Failed = (u8, String);

fn users_file(at: &Where) -> Result<PathBuf, Failed> {
    if let Some(f) = &at.users_file {
        return Ok(f.clone());
    }
    let path = at
        .config
        .as_ref()
        .ok_or((2, "need --config or --users-file".to_string()))?;
    let src = std::fs::read_to_string(path).map_err(|e| (2, format!("{}: {e}", path.display())))?;
    let cfg = config::parse(&src).config.ok_or_else(|| {
        (
            2,
            format!(
                "{} is invalid; check it with `routelith ctl verify`",
                path.display()
            ),
        )
    })?;
    Ok(cfg.server.users_file)
}

fn role(s: &str) -> Result<Role, Failed> {
    Role::parse(s).ok_or_else(|| (1, format!("role {s:?}: use {}", Role::NAMES.join(", "))))
}

fn password(from_stdin: bool) -> Result<String, Failed> {
    let pw = if from_stdin {
        let mut line = String::new();
        std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(|e| (2, format!("cannot read standard input: {e}")))?;
        line.trim_end_matches(['\r', '\n']).to_string()
    } else {
        let read = |prompt: &str| {
            rpassword::prompt_password(prompt).map_err(|e| {
                (
                    2,
                    format!("cannot read the password ({e}); use --password-stdin"),
                )
            })
        };
        let a = read("Password: ")?;
        if a.chars().count() >= MIN_PASSWORD && read("Again: ")? != a {
            return Err((1, "the passwords differ".to_string()));
        }
        a
    };
    if pw.chars().count() < MIN_PASSWORD {
        return Err((
            1,
            format!("the password must have at least {MIN_PASSWORD} characters"),
        ));
    }
    Ok(pw)
}

fn user(args: UserArgs) -> Result<String, Failed> {
    let path = users_file(&args.at)?;
    let mut users = Users::load(&path).map_err(|e| (2, e))?;
    let shown = path.display();
    let msg = match args.action {
        UserAction::List => {
            if users.is_empty() {
                return Ok(format!("{shown}: no users, so the web UI needs no login"));
            }
            let width = users.users.iter().map(|u| u.name.len()).max().unwrap_or(0);
            return Ok(users
                .users
                .iter()
                .map(|u| format!("{:width$}  {}", u.name, u.role))
                .collect::<Vec<_>>()
                .join("\n"));
        }
        UserAction::Add {
            name,
            role: r,
            password_stdin,
        } => {
            check_name(&name).map_err(|e| (1, e))?;
            let role = role(&r)?;
            if users.get(&name).is_some() {
                return Err((
                    1,
                    format!(
                        "{name:?} already exists; change it with `ctl user passwd` or `ctl user role`"
                    ),
                ));
            }
            let hash = hash_password(&password(password_stdin)?).map_err(|e| (2, e))?;
            let first = users.is_empty();
            users.users.push(User {
                name: name.clone(),
                role,
                password: hash,
            });
            if first {
                format!(
                    "added {name} ({role}) to {shown}; the web UI now needs a login \
                     unless anonymous = true"
                )
            } else {
                format!("added {name} ({role}) to {shown}")
            }
        }
        UserAction::Passwd {
            name,
            password_stdin,
        } => {
            let i = index(&users, &name)?;
            users.users[i].password =
                hash_password(&password(password_stdin)?).map_err(|e| (2, e))?;
            format!("changed the password of {name}")
        }
        UserAction::Role { name, role: r } => {
            let i = index(&users, &name)?;
            let role = role(&r)?;
            users.users[i].role = role;
            format!("{name} is now {role}")
        }
        UserAction::Remove { name } => {
            let i = index(&users, &name)?;
            users.users.remove(i);
            if users.is_empty() {
                format!("removed {name}; with no users left, the web UI needs no login")
            } else {
                format!("removed {name}")
            }
        }
    };
    users.save(&path).map_err(|e| (2, e))?;
    Ok(msg)
}

fn index(users: &Users, name: &str) -> Result<usize, Failed> {
    users
        .users
        .iter()
        .position(|u| u.name == name)
        .ok_or_else(|| (1, format!("no user {name:?}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(action: UserAction, file: &std::path::Path) -> UserArgs {
        UserArgs {
            action,
            at: Where {
                config: None,
                users_file: Some(file.to_path_buf()),
            },
        }
    }

    #[test]
    fn users_are_added_changed_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("users.toml");
        let listed = user(args(UserAction::List, &file)).unwrap();
        assert!(listed.contains("no users"), "{listed}");

        // Passwords come from standard input in tests: none here, so too
        // short, and nothing is written.
        let err = user(args(
            UserAction::Add {
                name: "ann".into(),
                role: "operator".into(),
                password_stdin: true,
            },
            &file,
        ))
        .unwrap_err();
        assert_eq!(err.0, 1, "{}", err.1);
        assert!(!file.exists());

        let mut u = Users::default();
        u.users.push(User {
            name: "ann".into(),
            role: Role::Viewer,
            password: hash_password("a long password").unwrap(),
        });
        u.save(&file).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&file).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        user(args(
            UserAction::Role {
                name: "ann".into(),
                role: "admin".into(),
            },
            &file,
        ))
        .unwrap();
        let listed = user(args(UserAction::List, &file)).unwrap();
        assert_eq!(listed, "ann  admin");
        let err = user(args(
            UserAction::Role {
                name: "ann".into(),
                role: "root".into(),
            },
            &file,
        ))
        .unwrap_err();
        assert!(err.1.contains("viewer, operator, admin"), "{}", err.1);
        let err = user(args(UserAction::Remove { name: "bob".into() }, &file)).unwrap_err();
        assert_eq!(err, (1, "no user \"bob\"".to_string()));
        let msg = user(args(UserAction::Remove { name: "ann".into() }, &file)).unwrap();
        assert!(msg.contains("needs no login"), "{msg}");
        assert!(Users::load(&file).unwrap().is_empty());
    }
}
