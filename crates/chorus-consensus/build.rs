fn main() {
    println!("cargo:rerun-if-changed=proto/openraft.proto");
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["proto/openraft.proto"], &["proto"])
        .expect("compile OpenRaft transport protobuf");
}
