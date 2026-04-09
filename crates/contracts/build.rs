fn main() {
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed=proto/auth.proto");
    println!("cargo:rerun-if-changed=proto/public.proto");
    println!("cargo:rerun-if-changed=proto/core.proto");
    println!("cargo:rerun-if-changed=proto/storage.proto");
    println!("cargo:rerun-if-changed=proto/export.proto");
    println!("cargo:rerun-if-changed=proto/logs.proto");
    println!("cargo:rerun-if-changed=proto/users.proto");
    println!("cargo:rerun-if-changed=proto/api_clients.proto");
    println!("cargo:rerun-if-changed=proto/billing.proto");
    println!("cargo:rerun-if-changed=proto/auth_context.proto");
    println!("cargo:rerun-if-changed=proto/common.proto");

    let protoc_path = protoc_bin_vendored::protoc_bin_path().expect("failed to find protoc");
    // Safety: this build script runs in a single-process context for this crate build.
    unsafe {
        std::env::set_var("PROTOC", protoc_path);
    }

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .type_attribute(".wildon.billing.v1", "#[derive(serde::Serialize)]")
        .type_attribute(
            ".wildon.logs.v1",
            "#[derive(serde::Serialize, serde::Deserialize)]",
        )
        .compile_protos(
            &[
                "proto/auth.proto",
                "proto/public.proto",
                "proto/core.proto",
                "proto/storage.proto",
                "proto/export.proto",
                "proto/logs.proto",
                "proto/users.proto",
                "proto/api_clients.proto",
                "proto/billing.proto",
                "proto/auth_context.proto",
                "proto/common.proto",
            ],
            &["proto"],
        )
        .expect("failed to compile proto contracts");
}
