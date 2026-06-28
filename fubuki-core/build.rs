fn main() {
    #[cfg(feature = "web")]
    {
        use static_files::NpmBuild;

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("fubuki-webui");

        NpmBuild::new(dir.to_str().unwrap())
            .install().unwrap()
            .run("build").unwrap()
            .target(dir.join("dist/fubuki-webui").to_str().unwrap())
            .to_resource_dir()
            .build().unwrap();
    }
}
