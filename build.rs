fn main() {
    #[cfg(target_os = "windows")]
    {
        #[allow(unused_mut)]
        let mut res = winres::WindowsResource::new();
        res.compile().unwrap();
    }
}
