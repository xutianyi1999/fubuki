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

    #[cfg(target_os = "windows")]
    {
        #[allow(unused_mut)]
        let mut res = winres::WindowsResource::new();

        #[cfg(feature = "gui")]
        res.set_manifest(r#"
        <assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
        <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
            <security>
                <requestedPrivileges>
                    <requestedExecutionLevel level="requireAdministrator" uiAccess="false" />
                </requestedPrivileges>
            </security>
        </trustInfo>
        </assembly>
        "#);

        res.compile()
            .unwrap();
    }
}