fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("icon.ico");

        res.set("FileDescription", "NightReign Save File Decrypter and Boss Reader");
        res.set("ProductName", "Nightlord Checker");
        res.set("OriginalFilename", "nightlord_checker.exe");
        res.set("CompanyName", "arcahn8");
        res.set("LegalCopyright", "Copyright © 2026");

        res.compile().unwrap();
    }
}
