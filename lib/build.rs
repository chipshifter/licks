use std::path::{Path, PathBuf};

fn main() {
    let proto_path = Path::new("protos");

    let output_dir = Path::new("./src/generated/");

    if !output_dir.exists() {
        std::fs::create_dir_all(output_dir).expect("can create directory at given path");
    }

    // (List of protobuf files to include into file, assumed generated file name, file that imports it)
    let proto_sets = [(
        [
            "blinded_address",
            "empty",
            "credentials",
            "registration",
            "identifiers",
            "message_wire",
            "signed_payload",
            "application_message",
        ]
        .as_slice(),
        "wire",
        "./src/api/connection/proto.rs",
    )];

    // Recompile when we update the path with all the protobuf files
    if let Some(proto_path) = proto_path.to_str() {
        println!("cargo:rerun-if-changed={proto_path}");
    }
    for set in proto_sets {
        // Recompile if changes are made in the importing file
        println!("cargo:rerun-if-changed={}", set.2);

        // get a Vector of all the paths to protobuf files we want to compile
        let proto_paths: Vec<PathBuf> = set
            .0
            .iter()
            .map(|&file_name| {
                let mut buf = proto_path.to_owned();
                buf.push(file_name);
                buf.set_extension("proto");
                buf
            })
            .collect();

        prost_build::Config::new()
            .default_package_filename(set.1)
            .out_dir(output_dir)
            .compile_protos(&proto_paths, &[proto_path])
            .expect("protos are valid and should compile");
    }
}
