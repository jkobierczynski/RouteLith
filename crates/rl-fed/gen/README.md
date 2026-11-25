# rl-fed-gen

Regenerates `../src/pb.rs` from `../proto/agent.proto`. Run `cargo run` in
this directory after changing the protocol and commit both files. It
brings its own `protoc` (protoc-bin-vendored) and needs Rust 1.88 or newer;
the generated code itself builds on the workspace MSRV.
