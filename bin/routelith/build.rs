//! On Windows, builds the Event Log message table into routelith.exe, so
//! Event Viewer shows routelith's events as text once the event source is
//! registered (doc §11.3, F8).

use std::path::PathBuf;

include!("build/messages.rs");

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=build/messages.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"));
    let table = out.join("messages.bin");
    std::fs::write(&table, message_table()).expect("write messages.bin");
    let rc = out.join("messages.rc");
    // Language neutral: found whatever the reader's language.
    let script = format!(
        "LANGUAGE 0, 0\n1 MESSAGETABLE \"{}\"\n",
        table.display().to_string().replace('\\', "/")
    );
    std::fs::write(&rc, script).expect("write messages.rc");
    embed_resource::compile(&rc, embed_resource::NONE)
        .manifest_optional()
        .expect("compile the message table resource");
}
