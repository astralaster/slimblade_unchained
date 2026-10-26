//! Flashes a locally built v4.49 container through the resident loader.
//!
//! Differs from `slimblade-cli`'s pinned artifacts only in the safety check:
//! the expected SHA-256 is supplied on the command line and compared against
//! the file before anything is erased. Every transfer step is the same shared
//! `transfer_payload` code the pinned path uses.

use std::path::Path;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use slimblade_image::sha256;
use slimblade_linux::flash::{transfer_payload, wait_for_queried_loader};
use slimblade_protocol::APPLICATION_PAYLOAD_OFFSET;

const APPLICATION_VENDOR: &str = "047d";
const APPLICATION_PRODUCT: &str = "80d7";
const SYSFS_USB_ROOT: &str = "/sys/bus/usb/devices";

fn hex(digest: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut text = String::with_capacity(64);
    for byte in digest {
        let _ = write!(text, "{byte:02x}");
    }
    text
}

fn read_sysfs(path: &Path, name: &str) -> Option<String> {
    std::fs::read_to_string(path.join(name))
        .ok()
        .map(|value| value.trim().to_owned())
}

/// Returns (sysfs name, bcdDevice) once the application is enumerating again.
fn find_application() -> Option<(String, String)> {
    let entries = std::fs::read_dir(SYSFS_USB_ROOT).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if read_sysfs(&path, "idVendor").as_deref() != Some(APPLICATION_VENDOR) {
            continue;
        }
        if read_sysfs(&path, "idProduct").as_deref() != Some(APPLICATION_PRODUCT) {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let bcd = read_sysfs(&path, "bcdDevice").unwrap_or_default();
        return Some((name, bcd));
    }
    None
}

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (Some(device), Some(container), Some(expected)) = (args.next(), args.next(), args.next())
    else {
        eprintln!("usage: rate-flash <loader-hidraw> <container.bin> <expected-sha256|any>");
        return ExitCode::from(2);
    };

    let image = match std::fs::read(&container) {
        Ok(image) => image,
        Err(error) => {
            eprintln!("cannot read {container}: {error}");
            return ExitCode::FAILURE;
        },
    };
    if image.len() != 128_112 {
        eprintln!("refusing: container is {} bytes, expected 128112", image.len());
        return ExitCode::FAILURE;
    }

    let digest = sha256(&image);
    let actual = hex(&digest);
    println!("container={container}");
    println!("sha256={actual}");
    if expected != "any" && expected != actual {
        eprintln!("refusing: expected {expected}");
        return ExitCode::FAILURE;
    }

    let payload = &image[APPLICATION_PAYLOAD_OFFSET as usize..];
    println!("payload={} bytes", payload.len());

    let mut loader = match wait_for_queried_loader(Path::new(&device), Duration::from_secs(8)) {
        Ok(loader) => loader,
        Err(error) => {
            eprintln!("no erase was attempted: {error}");
            return ExitCode::FAILURE;
        },
    };
    println!("loader=d2 device={device}");

    let mut next_percent = 5_usize;
    let blocks = match transfer_payload(
        loader.transport_mut(),
        payload,
        Duration::from_secs(30),
        |done, total| {
            let percent = done.saturating_mul(100).checked_div(total).unwrap_or(0);
            if percent >= next_percent || done == total {
                println!("write/verify: {percent}% ({done}/{total})");
                next_percent = percent.saturating_add(5);
            }
        },
    ) {
        Ok(blocks) => blocks,
        Err(error) => {
            eprintln!("flash failed after erase boundary: {error}");
            return ExitCode::FAILURE;
        },
    };
    drop(loader);

    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some((name, bcd)) = find_application() {
            println!("application={APPLICATION_VENDOR}:{APPLICATION_PRODUCT} bcdDevice={bcd} sysfs={name}");
            println!("flash complete: {blocks} blocks echoed");
            return ExitCode::SUCCESS;
        }
        if Instant::now() >= deadline {
            eprintln!("final block echoed, but the application did not return within 20 s");
            return ExitCode::FAILURE;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}
