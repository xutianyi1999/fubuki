fn main() {
    #[cfg(feature = "web")]
    {
        use static_files::NpmBuild;

        NpmBuild::new("./web")
            .install().unwrap() // runs npm install
            .run("build").unwrap() // runs npm run build
            .target("./web/dist")
            .to_resource_dir()
            .build().unwrap();
    }
}