#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    let _ = std::panic::catch_unwind(|| {
        let _ = datadoctor_forensic::registry::RegistryParser::parse_hive_data(data);
    });

    let _ = std::panic::catch_unwind(|| {
        let _ = datadoctor_forensic::registry::RegistryParser::load_from_data(data);
    });

    let _ = std::panic::catch_unwind(|| {
        let mut mutated = data.to_vec();
        if mutated.len() >= 4 {
            mutated[0] = b'r';
            mutated[1] = b'e';
            mutated[2] = b'g';
            mutated[3] = b'f';
        }
        let _ = datadoctor_forensic::registry::RegistryParser::parse_hive_data(&mutated);
    });

    if data.len() >= 64 {
        let _ = std::panic::catch_unwind(|| {
            let mut mutated = data.to_vec();
            mutated[0] = b'r';
            mutated[1] = b'e';
            mutated[2] = b'g';
            mutated[3] = b'f';

            if let Ok(parser) = datadoctor_forensic::registry::RegistryParser::load_from_data(&mutated) {
                let _ = parser.root_key();
                let _ = parser.extract_user_activity();
                let _ = parser.extract_installed_software();
                let _ = parser.get_value("Software\\Microsoft\\Windows\\CurrentVersion\\Run", "test");
            }
        });
    }
});
