fn main() {
    #[cfg(feature = "web")]
    {
        use static_files::NpmBuild;

        NpmBuild::new("./fubuki-webui")
            .install().unwrap() // runs npm install
            .run("build").unwrap() // runs npm run build
            .target("./fubuki-webui/dist")
            .to_resource_dir()
            .build().unwrap();
    }
}