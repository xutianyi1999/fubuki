fn main() {
    #[cfg(feature = "web")]
    {
        use static_files::NpmBuild;

        NpmBuild::new("./fubuki-webui")
            .install().unwrap() // runs npm install
            .run("build").unwrap() // runs npm run build
            .target("./fubuki-webui/dist/fubuki-webui")
            .to_resource_dir()
            .build().unwrap();
    }

    #[cfg(all(target_os = "windows", feature = "gui"))]
    {
        let mut res = winres::WindowsResource::new();

        res.set_manifest(r#"
        <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
        <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
            <security>
                <requestedPrivileges>
                    <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
                </requestedPrivileges>
            </securty>
        </trustInfo>
        </assembly>
        "#);

        res.compile()
            .unwrap();
    }
}