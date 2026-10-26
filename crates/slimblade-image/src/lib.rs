use core::fmt;

use sha2::{Digest, Sha256};
use slimblade_protocol::updater_crc32;

pub const HEADER_SIZE: usize = 16;
pub const STACK_HEADER_OFFSET: usize = 0x1f70;
pub const APPLICATION_PREFIX_OFFSET: usize = 0x2000;
pub const APPLICATION_HEADER_OFFSET: usize = 0x2010;
pub const APPLICATION_CODE_OFFSET: usize = 0x2020;
pub const OFFICIAL_APPLICATION_END_OFFSET: usize = 0x1f470;
pub const APPLICATION_UID: u32 = 0x4242_4242;
pub const STACK_UID: u32 = 0x5353_5353;
pub const CRC_UNCHECKED: u8 = 0xff;
pub const SECTION_UNKNOWN: u8 = 0xff;
pub const ROM_VERSION: u16 = 1;
pub const OFFICIAL_V449_SIZE: usize = 128_112;
pub const V449_USB_DESCRIPTOR_OFFSET: usize = 0x1e7d1;
pub const V449_BCD_DEVICE_OFFSET: usize = V449_USB_DESCRIPTOR_OFFSET + 12;

const OFFICIAL_V449_SHA256: [u8; 32] =
    parse_sha256("e91502e8021e61c97a77fb12324e99ee4acb23bee55a5a67d18e26521ef856f7");
const V449_USB_DESCRIPTOR: [u8; 18] = [
    0x12, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x40, 0x7d, 0x04, 0xd7, 0x80, 0x49, 0x04, 0x01, 0x02,
    0x00, 0x01,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactIdentity {
    pub name: &'static str,
    pub code_sha256: [u8; 32],
    pub container_sha256: Option<[u8; 32]>,
}

impl ArtifactIdentity {
    #[must_use]
    pub fn code_matches(self, code: &[u8]) -> bool {
        sha256(code) == self.code_sha256
    }

    #[must_use]
    pub fn container_matches(self, container: &[u8]) -> Option<bool> {
        self.container_sha256
            .map(|expected| sha256(container) == expected)
    }
}

pub const REFERENCE_ARTIFACTS: [ArtifactIdentity; 29] = [
    ArtifactIdentity {
        name: "stock-startup-reference",
        code_sha256: parse_sha256(
            "60d7616f48e2e457787e28748aec0b8afd404af35094cc8ef6b74c660c9248d8",
        ),
        container_sha256: None,
    },
    ArtifactIdentity {
        name: "stock-interrupt-wrappers",
        code_sha256: parse_sha256(
            "02e811fe3f434dd0fc697621bfbdc9cd74eee2d1e5d16df93f94f15fe7e5df9d",
        ),
        container_sha256: None,
    },
    ArtifactIdentity {
        name: "recovery-carrier",
        code_sha256: parse_sha256(
            "6dfab1b623c6fbd8daa6be71bdb3bfad1e90808da90956dc671c0165544dbd2e",
        ),
        container_sha256: Some(parse_sha256(
            "e555d5e17edc84cb8799d035d6193f6f664c1df9116bcba3c49faef1609221e8",
        )),
    },
    ArtifactIdentity {
        name: "reset-trampoline",
        code_sha256: parse_sha256(
            "eb26dace22b23177e84b62225949e573cd2b2764add0a722411733f3cb2a57f2",
        ),
        container_sha256: Some(parse_sha256(
            "bad4a3a7bdf3610e8b6cf0d9b1bb27f4d147ffa0efb242f24c0257bb454c6905",
        )),
    },
    ArtifactIdentity {
        name: "startup-trampoline-v4.53",
        code_sha256: parse_sha256(
            "0e24e9ffbf218afabde39043b177f19e29761b3175b772351fb6f7a839a800f7",
        ),
        container_sha256: Some(parse_sha256(
            "dccea5665710e9aebe039a83d49d07a1a0b32efc3826c7367814f5512ececa7b",
        )),
    },
    ArtifactIdentity {
        name: "standalone-recovery-stub",
        code_sha256: parse_sha256(
            "d88b2cd9211d9c46914062770e024f409dcee75ec826e70e80f6ff9a9e353bfe",
        ),
        container_sha256: Some(parse_sha256(
            "34daf13778a79034cc3a35917fbe6cfacc0b2f93db650e50f1f4df98ecf7e618",
        )),
    },
    ArtifactIdentity {
        name: "marker-first-hang-guard",
        code_sha256: parse_sha256(
            "93eef0420d1a54e4ca7efbfa1ca6a30e79044ff91b4294584ab062b7c6e061c0",
        ),
        container_sha256: Some(parse_sha256(
            "7bb3055bc1575bcb9ca4eab9ba2a83a3dbaba131e92cca78fffb18397cc2d19a",
        )),
    },
    ArtifactIdentity {
        name: "marker-first-usb-recovery-probe",
        code_sha256: parse_sha256(
            "cbe5bbbb119885f9d5b861b5548371a80672ada9b0ad9014069f12c8e41a9eca",
        ),
        container_sha256: Some(parse_sha256(
            "3ce23e3b9af4a1e713bad622f56fc9055cb178ca1ec198c7556c1dee44169e5a",
        )),
    },
    ArtifactIdentity {
        name: "marker-first-stock-harness",
        code_sha256: parse_sha256(
            "a26b3d8d9d2b45a79ccb80792d3dd8b5e40d47a07e539bc0e88ef72c9fc7c981",
        ),
        container_sha256: Some(parse_sha256(
            "cac3bab34545a2e20ad545af5b91c4a55db1c9cacfdcb0f45e4a348b65e3b356",
        )),
    },
    ArtifactIdentity {
        name: "late-marker-compatibility-probe",
        code_sha256: parse_sha256(
            "6d9988870062ce4d961ed88f92820ba63cca49dfa96196347a69e1b98d62b87a",
        ),
        container_sha256: Some(parse_sha256(
            "76669e150983725954fec510eb0c6717f84e08ef2a1a8ef3fb59cb49f7566905",
        )),
    },
    ArtifactIdentity {
        name: "marker-first-experiment-entry-probe",
        code_sha256: parse_sha256(
            "f8f97b226a2d293560bb2103ee6d0c0cd9a026c3260798795946c2b3c05f6897",
        ),
        container_sha256: Some(parse_sha256(
            "bc3275a95a0ebd4f3c12863ed2607d5f9ce026903ef19f145e177834f1a988b3",
        )),
    },
    ArtifactIdentity {
        name: "marker-first-rust-response-probe",
        code_sha256: parse_sha256(
            "964b064a5ab6e5b3149caa3d002d12a04c2b7b37d5569ca058de7898bcdc573e",
        ),
        container_sha256: Some(parse_sha256(
            "93e939ffdf19a7d862108182528fac7d9b066e59fa853b21327bedd6260b14d4",
        )),
    },
    ArtifactIdentity {
        name: "post-init-hook-probe",
        code_sha256: parse_sha256(
            "24be6b6c2ae93694216d61043f54e0b7840a70f332e450888cc28773a252f7b5",
        ),
        container_sha256: Some(parse_sha256(
            "133f5241efecc23c7cc2fffcc0fdb34c37f5a3f840362938c27a2bc5353c1de1",
        )),
    },
    ArtifactIdentity {
        name: "wired-loop-hook-probe",
        code_sha256: parse_sha256(
            "5a99f4d7ab6972f05724980a9d960f5b4d279212af3866ff8cb3c8a8b3b5dac0",
        ),
        container_sha256: Some(parse_sha256(
            "61cf9ebc9b7739fbc586a6949a1dbca2f754f07b6e3e7ea16a4319c6d365bd87",
        )),
    },
    ArtifactIdentity {
        name: "active-loop-hook-probe",
        code_sha256: parse_sha256(
            "aca3fcb6c3182a695667d96e2068e6e762698ae9f4f021cd3725d1ee6e308044",
        ),
        container_sha256: Some(parse_sha256(
            "bf7aab32e3c32b4bf3853a7c79de21e5818961fbeb70239c95b40db7d898d077",
        )),
    },
    ArtifactIdentity {
        name: "steady-loop-hook-probe",
        code_sha256: parse_sha256(
            "df9df61f1b22393b242a24e9943795ea80bacb84cc3042ccae9a9e202bd8fc41",
        ),
        container_sha256: Some(parse_sha256(
            "3defe9f5fda2ebaefb923fbe1c62fdd877345ccb75f6b1eec2604e731688d310",
        )),
    },
    ArtifactIdentity {
        name: "dispatcher-return-hook-probe",
        code_sha256: parse_sha256(
            "76e71f9937c503d709370bec7b889a2d974f655e571978de6f069332e22bdbbe",
        ),
        container_sha256: Some(parse_sha256(
            "e79d8a05f0ed65ae6f3059885e02899c1adbb10be3d320f30829d1e8623b2656",
        )),
    },
    ArtifactIdentity {
        name: "experiment-dispatch-guard",
        code_sha256: parse_sha256(
            "218eca02efff1692aa2c47603e11369c848f94f235f31c6cb50432efa0fdd8fb",
        ),
        container_sha256: Some(parse_sha256(
            "dd720ba30fc05b9c401eb1f182f62bb217a57a03a3788ccc421806e06f30ac48",
        )),
    },
    ArtifactIdentity {
        name: "input-diagnostics",
        code_sha256: parse_sha256(
            "b4bef493b1b5f2e49c5e880f307dad8c633e8d5b3e78849deb32ba7f26fc1928",
        ),
        container_sha256: Some(parse_sha256(
            "4a90ccf453b80cbbf4018dfec87d14051dfff3ea076445822c28dfbc3e4f55a3",
        )),
    },
    ArtifactIdentity {
        name: "paged-input-diagnostics",
        code_sha256: parse_sha256(
            "3e17a0b58cef059ace43d43bf4d957f65cf2ef29f14711ca0205e4a8e9e34a65",
        ),
        container_sha256: Some(parse_sha256(
            "c5fb2b865c6ba1993c673f989e5c811bfa661b31f8c6261d2ab04e95eab5692f",
        )),
    },
    ArtifactIdentity {
        name: "sensor-shadow-diagnostics",
        code_sha256: parse_sha256(
            "c8ddcddb97770a1d6bf4d0c0bf9a35fbbec7cc46a7656330d675119aee98f6ef",
        ),
        container_sha256: Some(parse_sha256(
            "111f22eaf0db16bf2df2ba29187c9fbf151ca578385a5ad288c31b3f064657e4",
        )),
    },
    ArtifactIdentity {
        name: "unsolicited-report-probe",
        code_sha256: parse_sha256(
            "85182857013afa4fe091a31691cc2c43163afd6b9d39fee6b907bac73a5fe8fb",
        ),
        container_sha256: Some(parse_sha256(
            "342b8e7ed2891e9b495eaa6078bb738241a7dc49be67d61506d248ce4aafcf21",
        )),
    },
    ArtifactIdentity {
        name: "custom-main-handoff-probe",
        code_sha256: parse_sha256(
            "a99871f28c1ee714959376bb008447f874e0bcdaaed3c21d09931df78d98739a",
        ),
        container_sha256: Some(parse_sha256(
            "401ab888a8512fa6ff74058fc78d329a3e4a34064614542ea3716d06be8dbf97",
        )),
    },
    ArtifactIdentity {
        name: "custom-main-usb-recovery-probe",
        code_sha256: parse_sha256(
            "af65cdb33e14e99b0a253874d65a06c86ebb0d43937df640c42c6c5657907f18",
        ),
        container_sha256: Some(parse_sha256(
            "7c044eb8381b87ea3e383a114c066c569040b16c1becdfe079d4940a4392d7fa",
        )),
    },
    ArtifactIdentity {
        name: "custom-main-stream-transport-probe",
        code_sha256: parse_sha256(
            "54b54999d5aab57900cb47f3521c92b1807dbdb2a988bf8afd805fd6f6d02124",
        ),
        container_sha256: Some(parse_sha256(
            "31c14d3a51a94ccc8f2d5337bae15b3755ee7665804d56416ac518d44decb489",
        )),
    },
    ArtifactIdentity {
        name: "custom-main-stream-transport-runtime",
        code_sha256: parse_sha256(
            "9dba72994d1356fabe977f8c8d4a9af980302465839991322fade7e439e4b672",
        ),
        container_sha256: None,
    },
    ArtifactIdentity {
        name: "custom-main-sensor-stream-probe",
        code_sha256: parse_sha256(
            "aa0991589fc2242a19fd824742b567344e33aa60270e4466ba65e01146980a79",
        ),
        container_sha256: Some(parse_sha256(
            "65c7dfd35d4f97751db74899c076c27741dd290d045fbd130aa854443b60edf8",
        )),
    },
    ArtifactIdentity {
        name: "custom-main-sensor-stream-runtime",
        code_sha256: parse_sha256(
            "febc0f904f4cf3bd98caa4900862fc5573a43204a32e2e0fed32542e9bebe293",
        ),
        container_sha256: None,
    },
    ArtifactIdentity {
        name: "custom-main-sensor-stream-support",
        code_sha256: parse_sha256(
            "c85b576bebf9044dc38848eb9e9d0260544b8b3c3793720ae296f8263ce4213b",
        ),
        container_sha256: None,
    },
];

pub const STOCK_STARTUP_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[0];
pub const STOCK_INTERRUPT_WRAPPERS_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[1];
pub const RECOVERY_CARRIER_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[2];
pub const RESET_TRAMPOLINE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[3];
pub const STARTUP_TRAMPOLINE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[4];
pub const RECOVERY_STUB_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[5];
pub const RECOVERY_GUARD_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[6];
pub const USB_RECOVERY_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[7];
pub const STOCK_HARNESS_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[8];
pub const LATE_MARKER_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[9];
pub const EXPERIMENT_ENTRY_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[10];
pub const RUST_RESPONSE_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[11];
pub const POST_INIT_HOOK_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[12];
pub const WIRED_LOOP_HOOK_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[13];
pub const ACTIVE_LOOP_HOOK_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[14];
pub const STEADY_LOOP_HOOK_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[15];
pub const DISPATCHER_RETURN_HOOK_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[16];
pub const EXPERIMENT_DISPATCH_GUARD_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[17];
pub const INPUT_DIAGNOSTICS_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[18];
pub const PAGED_INPUT_DIAGNOSTICS_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[19];
pub const SENSOR_SHADOW_DIAGNOSTICS_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[20];
pub const UNSOLICITED_REPORT_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[21];
pub const CUSTOM_MAIN_HANDOFF_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[22];
pub const CUSTOM_MAIN_USB_RECOVERY_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[23];
pub const CUSTOM_MAIN_STREAM_TRANSPORT_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[24];
pub const CUSTOM_MAIN_STREAM_TRANSPORT_RUNTIME_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[25];
pub const CUSTOM_MAIN_SENSOR_STREAM_PROBE_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[26];
pub const CUSTOM_MAIN_SENSOR_STREAM_RUNTIME_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[27];
pub const CUSTOM_MAIN_SENSOR_STREAM_SUPPORT_ARTIFACT: ArtifactIdentity = REFERENCE_ARTIFACTS[28];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FirmwareIdentity {
    pub name: &'static str,
    pub container_size: usize,
    pub container_sha256: [u8; 32],
    pub payload_offset: usize,
    pub payload_size: usize,
    pub payload_sha256: [u8; 32],
    pub payload_crc: u32,
}

impl FirmwareIdentity {
    /// Verifies a container and returns its application payload.
    ///
    /// # Errors
    ///
    /// Returns an error when the recorded container or payload identity does not match, or when
    /// the recorded payload offset is outside the image.
    pub fn validate(self, image: &[u8]) -> Result<&[u8], FirmwareIdentityError> {
        let container_sha256 = sha256(image);
        if image.len() != self.container_size || container_sha256 != self.container_sha256 {
            return Err(FirmwareIdentityError::ContainerMismatch {
                name: self.name,
                size: image.len(),
                sha256: container_sha256,
            });
        }
        let payload = image.get(self.payload_offset..).ok_or(
            FirmwareIdentityError::PayloadOffsetOutOfBounds {
                name: self.name,
                offset: self.payload_offset,
                size: image.len(),
            },
        )?;
        let payload_sha256 = sha256(payload);
        let payload_crc = updater_crc32(payload);
        if payload.len() != self.payload_size
            || payload_sha256 != self.payload_sha256
            || payload_crc != self.payload_crc
        {
            return Err(FirmwareIdentityError::PayloadMismatch {
                name: self.name,
                size: payload.len(),
                sha256: payload_sha256,
                crc: payload_crc,
            });
        }
        Ok(payload)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FirmwareIdentityError {
    ContainerMismatch {
        name: &'static str,
        size: usize,
        sha256: [u8; 32],
    },
    PayloadOffsetOutOfBounds {
        name: &'static str,
        offset: usize,
        size: usize,
    },
    PayloadMismatch {
        name: &'static str,
        size: usize,
        sha256: [u8; 32],
        crc: u32,
    },
}

impl fmt::Display for FirmwareIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ContainerMismatch { name, size, .. } => {
                write!(f, "{name} container identity mismatch ({size} bytes)")
            },
            Self::PayloadOffsetOutOfBounds { name, offset, size } => write!(
                f,
                "{name} payload offset {offset:#x} is beyond {size}-byte container"
            ),
            Self::PayloadMismatch {
                name, size, crc, ..
            } => write!(
                f,
                "{name} payload identity mismatch ({size} bytes, CRC {crc:08x})"
            ),
        }
    }
}

impl core::error::Error for FirmwareIdentityError {}

const fn firmware_identity(
    name: &'static str,
    container_sha256: &'static str,
    payload_sha256: &'static str,
    payload_crc: u32,
) -> FirmwareIdentity {
    FirmwareIdentity {
        name,
        container_size: OFFICIAL_V449_SIZE,
        container_sha256: parse_sha256(container_sha256),
        payload_offset: APPLICATION_PREFIX_OFFSET,
        payload_size: OFFICIAL_V449_SIZE - APPLICATION_PREFIX_OFFSET,
        payload_sha256: parse_sha256(payload_sha256),
        payload_crc,
    }
}

pub const OFFICIAL_V449: FirmwareIdentity = firmware_identity(
    "official-v4.49",
    "e91502e8021e61c97a77fb12324e99ee4acb23bee55a5a67d18e26521ef856f7",
    "3b7849cafa2a8d4a0c2694c9771d70563563dc1c6cdbf84ede9b8648071604bf",
    0xdd0f_e246,
);
pub const V449_DESCRIPTOR_PROBE: FirmwareIdentity = firmware_identity(
    "descriptor-probe-v4.50",
    "990079b8a71668f0e19963c71a70f8efac3f36e69a21133d60f9951cd8519081",
    "46520d851e5c908500e89f48fc05880c60fc43fb17367aeb6c109b3f0ce3ee88",
    0xbe3f_edce,
);
pub const RECOVERY_CARRIER: FirmwareIdentity = firmware_identity(
    "recovery-carrier-v4.51",
    "e555d5e17edc84cb8799d035d6193f6f664c1df9116bcba3c49faef1609221e8",
    "aac81065cc171f263d54c4bb64019bd2fa250d032640fcd7415fbb4caf8b2899",
    0xcbd4_f74b,
);
pub const RESET_TRAMPOLINE: FirmwareIdentity = firmware_identity(
    "reset-trampoline-v4.52",
    "bad4a3a7bdf3610e8b6cf0d9b1bb27f4d147ffa0efb242f24c0257bb454c6905",
    "0bae1c229db988c03f6eb55b78a726d69fdf1f42048694a404335f00b950028a",
    0xdb03_4cd6,
);
pub const STARTUP_TRAMPOLINE: FirmwareIdentity = firmware_identity(
    "startup-trampoline-v4.53",
    "dccea5665710e9aebe039a83d49d07a1a0b32efc3826c7367814f5512ececa7b",
    "da04628aa7e05ee253b63a4984b2ceb138d91029f239f11efd6914b0da9afc8a",
    0x4e9c_5e53,
);
pub const RECOVERY_STUB: FirmwareIdentity = firmware_identity(
    "standalone-recovery-stub",
    "34daf13778a79034cc3a35917fbe6cfacc0b2f93db650e50f1f4df98ecf7e618",
    "67415f19bf43ea3f91fe1ec223bad5c69d3e6975cf42aba60219a8bfd1457ea6",
    0x6e47_3ed7,
);
pub const RECOVERY_GUARD: FirmwareIdentity = firmware_identity(
    "marker-first-hang-guard",
    "7bb3055bc1575bcb9ca4eab9ba2a83a3dbaba131e92cca78fffb18397cc2d19a",
    "3c11672dca070a246202b70b743456b4b5bb32b157d2e305e2f032499e36823c",
    0x2b64_f82e,
);
pub const USB_RECOVERY_PROBE: FirmwareIdentity = firmware_identity(
    "marker-first-usb-recovery-probe",
    "3ce23e3b9af4a1e713bad622f56fc9055cb178ca1ec198c7556c1dee44169e5a",
    "6e14eedaa65930bca93fa60febd43f966f310743c9c4c7c79084865990192f7d",
    0x2da6_b921,
);
pub const STOCK_HARNESS: FirmwareIdentity = firmware_identity(
    "marker-first-stock-harness-v4.55",
    "cac3bab34545a2e20ad545af5b91c4a55db1c9cacfdcb0f45e4a348b65e3b356",
    "2b2d8fa2ceacb3429e4624e19af506dcf6efb6a44614dc7bfe226f20adbe3e8b",
    0x2b53_d16e,
);
pub const LATE_MARKER_PROBE: FirmwareIdentity = firmware_identity(
    "late-marker-compatibility-probe-v4.56",
    "76669e150983725954fec510eb0c6717f84e08ef2a1a8ef3fb59cb49f7566905",
    "5131a96feeab48e5b492034ac436b0bb8c2996642eb8032a957aed273177573e",
    0xf3ce_f231,
);
pub const EXPERIMENT_ENTRY_PROBE: FirmwareIdentity = firmware_identity(
    "marker-first-experiment-entry-probe-v4.57",
    "bc3275a95a0ebd4f3c12863ed2607d5f9ce026903ef19f145e177834f1a988b3",
    "08a4201ef3d9656b720914ac86447fdae27463e0302f7edd6f4641186b3e8fa9",
    0x2381_ed73,
);
pub const RUST_RESPONSE_PROBE: FirmwareIdentity = firmware_identity(
    "marker-first-rust-response-probe-v4.58",
    "93e939ffdf19a7d862108182528fac7d9b066e59fa853b21327bedd6260b14d4",
    "1b1a76c85e0a94345ff54c47389f93fd9038a1c23a9755ace956c87f907fd24b",
    0x671c_f8a7,
);
pub const POST_INIT_HOOK_PROBE: FirmwareIdentity = firmware_identity(
    "post-init-hook-probe-v4.59",
    "133f5241efecc23c7cc2fffcc0fdb34c37f5a3f840362938c27a2bc5353c1de1",
    "612e188cf000d7ecdabd0dd5e030b0066c93f59a2abef21ac03e496c38559c20",
    0x8065_29df,
);
pub const WIRED_LOOP_HOOK_PROBE: FirmwareIdentity = firmware_identity(
    "wired-loop-hook-probe-v4.60",
    "61cf9ebc9b7739fbc586a6949a1dbca2f754f07b6e3e7ea16a4319c6d365bd87",
    "3336ed10de4883b22e79f77e0f937245e289615237016d15c1987aaf3189dfbd",
    0xd31d_c8f2,
);
pub const ACTIVE_LOOP_HOOK_PROBE: FirmwareIdentity = firmware_identity(
    "active-loop-hook-probe-v4.61",
    "bf7aab32e3c32b4bf3853a7c79de21e5818961fbeb70239c95b40db7d898d077",
    "dc240287646193279e2b46d582c635551ca64d020b81b5e68824e426c52ec40b",
    0xdf50_3f76,
);
pub const STEADY_LOOP_HOOK_PROBE: FirmwareIdentity = firmware_identity(
    "steady-loop-hook-probe-v4.62",
    "3defe9f5fda2ebaefb923fbe1c62fdd877345ccb75f6b1eec2604e731688d310",
    "49bb7e6406fa78aebb7df9df10b79fbd7785091dfea5da4a83b0a259f476ec37",
    0x8a54_4004,
);
pub const DISPATCHER_RETURN_HOOK_PROBE: FirmwareIdentity = firmware_identity(
    "dispatcher-return-hook-probe-v4.63",
    "e79d8a05f0ed65ae6f3059885e02899c1adbb10be3d320f30829d1e8623b2656",
    "257588ae7bcbfb1192221a0a2604ae10e776aab0c4526dc38ffcdf6992780191",
    0x860c_2809,
);
pub const EXPERIMENT_DISPATCH_GUARD: FirmwareIdentity = firmware_identity(
    "experiment-dispatch-guard-v4.64",
    "dd720ba30fc05b9c401eb1f182f62bb217a57a03a3788ccc421806e06f30ac48",
    "91069f91ac42e4621022514e04af0571ad5c9f52bbebcf192a8bdd9466a26e22",
    0x7057_4845,
);
pub const INPUT_DIAGNOSTICS: FirmwareIdentity = firmware_identity(
    "input-diagnostics-v4.65",
    "4a90ccf453b80cbbf4018dfec87d14051dfff3ea076445822c28dfbc3e4f55a3",
    "1c5854dc8b2e66a814a0dc5ebf41768a3ebcc58da83addbcb6b512b3090e6f59",
    0xef6a_b24a,
);
pub const PAGED_INPUT_DIAGNOSTICS: FirmwareIdentity = firmware_identity(
    "paged-input-diagnostics-v4.66",
    "c5fb2b865c6ba1993c673f989e5c811bfa661b31f8c6261d2ab04e95eab5692f",
    "6006faab993f9ba83b30a365376ad889dfcbf20af22de057e98d2c680516723d",
    0x7ed6_3bf1,
);
pub const SENSOR_SHADOW_DIAGNOSTICS: FirmwareIdentity = firmware_identity(
    "sensor-shadow-diagnostics-v4.70",
    "111f22eaf0db16bf2df2ba29187c9fbf151ca578385a5ad288c31b3f064657e4",
    "b465bd7d0a0f0379a767a9bbf6ba7f81aab52c9a265b9bafc462d89e64441475",
    0x96bd_3f6d,
);
pub const UNSOLICITED_REPORT_PROBE: FirmwareIdentity = firmware_identity(
    "unsolicited-report-probe-v4.71",
    "342b8e7ed2891e9b495eaa6078bb738241a7dc49be67d61506d248ce4aafcf21",
    "c7b6c7fedc423777f1f1ad46ae4c6b95e86ec38b4e72e4c06cf759345e7a0597",
    0x4b61_d5a9,
);
pub const CUSTOM_MAIN_HANDOFF_PROBE: FirmwareIdentity = firmware_identity(
    "custom-main-handoff-probe-v4.72",
    "401ab888a8512fa6ff74058fc78d329a3e4a34064614542ea3716d06be8dbf97",
    "3d5a0008095ca4ff3e486912842b619c8c9286b0e0702932345e644fb6ea0661",
    0x73c3_cfbe,
);
pub const CUSTOM_MAIN_USB_RECOVERY_PROBE: FirmwareIdentity = firmware_identity(
    "custom-main-usb-recovery-probe-v4.73",
    "7c044eb8381b87ea3e383a114c066c569040b16c1becdfe079d4940a4392d7fa",
    "10bd22194a19c0c27d5120b461a7ff7a2897871ad13a255225d6e9953fcb3b5d",
    0x7b3c_a402,
);
pub const CUSTOM_MAIN_STREAM_TRANSPORT_PROBE: FirmwareIdentity = firmware_identity(
    "custom-main-stream-transport-probe-v4.74",
    "31c14d3a51a94ccc8f2d5337bae15b3755ee7665804d56416ac518d44decb489",
    "964e7fa847e308fa51d173e1cac1ae3b97d61c73b9f82c03268341871768c362",
    0x105b_ca99,
);
pub const CUSTOM_MAIN_SENSOR_STREAM_PROBE: FirmwareIdentity = firmware_identity(
    "custom-main-sensor-stream-probe-v4.75",
    "65c7dfd35d4f97751db74899c076c27741dd290d045fbd130aa854443b60edf8",
    "b00d22b8ab6ae686cc6a3230324c971a57bf29a43e5236bd94ee8c69d05e4ae9",
    0xc430_b50f,
);

pub const FLASHABLE_IMAGES: [FirmwareIdentity; 26] = [
    OFFICIAL_V449,
    V449_DESCRIPTOR_PROBE,
    RECOVERY_CARRIER,
    RESET_TRAMPOLINE,
    STARTUP_TRAMPOLINE,
    RECOVERY_STUB,
    RECOVERY_GUARD,
    USB_RECOVERY_PROBE,
    STOCK_HARNESS,
    LATE_MARKER_PROBE,
    EXPERIMENT_ENTRY_PROBE,
    RUST_RESPONSE_PROBE,
    POST_INIT_HOOK_PROBE,
    WIRED_LOOP_HOOK_PROBE,
    ACTIVE_LOOP_HOOK_PROBE,
    STEADY_LOOP_HOOK_PROBE,
    DISPATCHER_RETURN_HOOK_PROBE,
    EXPERIMENT_DISPATCH_GUARD,
    INPUT_DIAGNOSTICS,
    PAGED_INPUT_DIAGNOSTICS,
    SENSOR_SHADOW_DIAGNOSTICS,
    UNSOLICITED_REPORT_PROBE,
    CUSTOM_MAIN_HANDOFF_PROBE,
    CUSTOM_MAIN_USB_RECOVERY_PROBE,
    CUSTOM_MAIN_STREAM_TRANSPORT_PROBE,
    CUSTOM_MAIN_SENSOR_STREAM_PROBE,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ImageHeader {
    pub offset: usize,
    pub crc: u32,
    pub version: u16,
    pub length_words: u16,
    pub uid: u32,
    pub crc_status: u8,
    pub section_status: u8,
    pub rom_version: u16,
}

impl ImageHeader {
    /// Calculates the exclusive end of the image region described by this header.
    ///
    /// # Errors
    ///
    /// Returns an error if the encoded length overflows the host address size.
    pub fn end_offset(self) -> Result<usize, ImageError> {
        let byte_length = usize::from(self.length_words)
            .checked_mul(4)
            .ok_or(ImageError::ArithmeticOverflow)?;
        self.offset
            .checked_add(byte_length)
            .ok_or(ImageError::ArithmeticOverflow)
    }

    /// Calculates the first payload byte following this header.
    ///
    /// # Errors
    ///
    /// Returns an error if the header offset arithmetic overflows.
    pub fn payload_offset(self) -> Result<usize, ImageError> {
        self.offset
            .checked_add(HEADER_SIZE)
            .ok_or(ImageError::ArithmeticOverflow)
    }

    /// Calculates the updater CRC for the region described by this header.
    ///
    /// # Errors
    ///
    /// Returns an error if the region arithmetic overflows or the region is outside `image`.
    pub fn calculate_crc(self, image: &[u8]) -> Result<u32, ImageError> {
        let end = self.end_offset()?;
        if end > image.len() {
            return Err(ImageError::RegionOutOfBounds {
                header_offset: self.offset,
                end,
                image_length: image.len(),
            });
        }
        let payload = self.payload_offset()?;
        if payload > end {
            return Err(ImageError::RegionBeforePayload {
                header_offset: self.offset,
                payload,
                end,
            });
        }
        let region = image
            .get(payload..end)
            .ok_or(ImageError::RegionOutOfBounds {
                header_offset: self.offset,
                end,
                image_length: image.len(),
            })?;
        Ok(updater_crc32(region))
    }

    /// Checks the stored CRC against the described payload.
    ///
    /// # Errors
    ///
    /// Returns an error if the region arithmetic overflows or the region is outside `image`.
    pub fn crc_is_valid(self, image: &[u8]) -> Result<bool, ImageError> {
        Ok(self.calculate_crc(image)? == self.crc)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImageError {
    HeaderOutOfBounds {
        offset: usize,
        image_length: usize,
    },
    RegionOutOfBounds {
        header_offset: usize,
        end: usize,
        image_length: usize,
    },
    RegionBeforePayload {
        header_offset: usize,
        payload: usize,
        end: usize,
    },
    EmptyApplication,
    EndBeforeCode {
        requested: usize,
        natural: usize,
    },
    EndNotAligned {
        requested: usize,
    },
    LengthWordsOverflow {
        words: usize,
    },
    OfficialImageMismatch {
        size: usize,
        sha256: [u8; 32],
    },
    DescriptorMismatch,
    ArithmeticOverflow,
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HeaderOutOfBounds {
                offset,
                image_length,
            } => write!(
                f,
                "no complete image header at {offset:#x} in {image_length}-byte image"
            ),
            Self::RegionOutOfBounds {
                header_offset,
                end,
                image_length,
            } => write!(
                f,
                "header at {header_offset:#x} ends beyond {image_length}-byte image at {end:#x}"
            ),
            Self::RegionBeforePayload {
                header_offset,
                payload,
                end,
            } => write!(
                f,
                "header at {header_offset:#x} ends at {end:#x}, before payload at {payload:#x}"
            ),
            Self::EmptyApplication => f.write_str("application code is empty"),
            Self::EndBeforeCode { requested, natural } => write!(
                f,
                "requested end {requested:#x} is before code end {natural:#x}"
            ),
            Self::EndNotAligned { requested } => write!(
                f,
                "requested application end {requested:#x} is not 16-byte aligned"
            ),
            Self::LengthWordsOverflow { words } => {
                write!(f, "application length {words} words exceeds header")
            },
            Self::OfficialImageMismatch { size, sha256 } => write!(
                f,
                "input is not recorded official v4.49 image: size={size}, sha256={sha256:02x?}"
            ),
            Self::DescriptorMismatch => {
                f.write_str("official v4.49 USB descriptor does not match expectation")
            },
            Self::ArithmeticOverflow => f.write_str("image offset arithmetic overflowed"),
        }
    }
}

impl core::error::Error for ImageError {}

/// Parses one fixed-format image header.
///
/// # Errors
///
/// Returns an error when offset arithmetic overflows or a complete header is unavailable.
#[allow(
    clippy::indexing_slicing,
    reason = "get() first proves that the returned slice contains the complete fixed-size header"
)]
pub fn parse_header(image: &[u8], offset: usize) -> Result<ImageHeader, ImageError> {
    let end = offset
        .checked_add(HEADER_SIZE)
        .ok_or(ImageError::ArithmeticOverflow)?;
    let bytes = image
        .get(offset..end)
        .ok_or(ImageError::HeaderOutOfBounds {
            offset,
            image_length: image.len(),
        })?;
    Ok(ImageHeader {
        offset,
        crc: u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        version: u16::from_le_bytes([bytes[4], bytes[5]]),
        length_words: u16::from_le_bytes([bytes[6], bytes[7]]),
        uid: u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
        crc_status: bytes[12],
        section_status: bytes[13],
        rom_version: u16::from_le_bytes([bytes[14], bytes[15]]),
    })
}

/// Finds and validates known stack and application headers.
///
/// # Errors
///
/// Returns an error when a recognized header describes an invalid image region.
pub fn inspect_headers(image: &[u8]) -> Result<Vec<ImageHeader>, ImageError> {
    let mut headers = Vec::with_capacity(2);
    for (offset, expected_uid) in [
        (STACK_HEADER_OFFSET, STACK_UID),
        (APPLICATION_HEADER_OFFSET, APPLICATION_UID),
    ] {
        if offset
            .checked_add(HEADER_SIZE)
            .is_none_or(|end| end > image.len())
        {
            continue;
        }
        let header = parse_header(image, offset)?;
        if header.uid == expected_uid {
            header.calculate_crc(image)?;
            headers.push(header);
        }
    }
    Ok(headers)
}

/// Wraps application code in the BK3635 application container format.
///
/// # Errors
///
/// Returns an error for empty code, invalid geometry, arithmetic overflow, or a length that does
/// not fit the on-device header.
#[allow(
    clippy::indexing_slicing,
    reason = "all written ranges are derived from the size of the newly allocated output image"
)]
pub fn make_application_container(
    code: &[u8],
    version: u16,
    end_offset: Option<usize>,
) -> Result<Vec<u8>, ImageError> {
    if code.is_empty() {
        return Err(ImageError::EmptyApplication);
    }
    let padded_length = code
        .len()
        .checked_add(15)
        .ok_or(ImageError::ArithmeticOverflow)?
        & !15;
    let natural_end = APPLICATION_CODE_OFFSET
        .checked_add(padded_length)
        .ok_or(ImageError::ArithmeticOverflow)?;
    let end = end_offset.unwrap_or(natural_end);
    if end < natural_end {
        return Err(ImageError::EndBeforeCode {
            requested: end,
            natural: natural_end,
        });
    }
    if !end.is_multiple_of(16) {
        return Err(ImageError::EndNotAligned { requested: end });
    }

    let region_length = end
        .checked_sub(APPLICATION_HEADER_OFFSET)
        .ok_or(ImageError::ArithmeticOverflow)?;
    let words = region_length / 4;
    let length_words =
        u16::try_from(words).map_err(|_| ImageError::LengthWordsOverflow { words })?;
    let mut image = vec![0xff; end];
    image[APPLICATION_CODE_OFFSET..APPLICATION_CODE_OFFSET + code.len()].copy_from_slice(code);
    let crc = updater_crc32(&image[APPLICATION_CODE_OFFSET..end]);
    write_header(
        &mut image[APPLICATION_HEADER_OFFSET..APPLICATION_CODE_OFFSET],
        crc,
        version,
        length_words,
        APPLICATION_UID,
    );
    Ok(image)
}

/// Recalculates and writes the CRC stored in a header.
///
/// # Errors
///
/// Returns an error when the header or its described image region is invalid.
#[allow(
    clippy::indexing_slicing,
    reason = "parse_header validates the header range before its four-byte CRC field is written"
)]
pub fn refresh_header_crc(image: &mut [u8], offset: usize) -> Result<(), ImageError> {
    let header = parse_header(image, offset)?;
    let crc = header.calculate_crc(image)?;
    let end = offset
        .checked_add(4)
        .ok_or(ImageError::ArithmeticOverflow)?;
    image[offset..end].copy_from_slice(&crc.to_le_bytes());
    Ok(())
}

/// Produces the recorded v4.50 USB-descriptor probe from an official v4.49 image.
///
/// # Errors
///
/// Returns an error unless the input has the exact recorded v4.49 identity and descriptor.
#[allow(
    clippy::indexing_slicing,
    reason = "exact v4.49 size and digest validation precedes access to its fixed descriptor fields"
)]
pub fn make_v449_descriptor_probe(image: &[u8]) -> Result<Vec<u8>, ImageError> {
    let digest = sha256(image);
    if image.len() != OFFICIAL_V449_SIZE || digest != OFFICIAL_V449_SHA256 {
        return Err(ImageError::OfficialImageMismatch {
            size: image.len(),
            sha256: digest,
        });
    }
    let descriptor_end = V449_USB_DESCRIPTOR_OFFSET + V449_USB_DESCRIPTOR.len();
    if image[V449_USB_DESCRIPTOR_OFFSET..descriptor_end] != V449_USB_DESCRIPTOR {
        return Err(ImageError::DescriptorMismatch);
    }

    let mut probe = image.to_vec();
    probe[V449_BCD_DEVICE_OFFSET] = 0x50;
    refresh_header_crc(&mut probe, APPLICATION_HEADER_OFFSET)?;
    refresh_header_crc(&mut probe, STACK_HEADER_OFFSET)?;
    Ok(probe)
}

#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[allow(
    clippy::indexing_slicing,
    reason = "the compile-time length assertion proves the literal contains every indexed digit"
)]
const fn parse_sha256(hex: &str) -> [u8; 32] {
    let input = hex.as_bytes();
    assert!(
        input.len() == 64,
        "SHA-256 literal must contain 64 hex digits"
    );
    let mut digest = [0_u8; 32];
    let mut index = 0;
    while index < digest.len() {
        digest[index] = (hex_nibble(input[index * 2]) << 4_u8) | hex_nibble(input[index * 2 + 1]);
        index += 1;
    }
    digest
}

#[allow(
    clippy::panic,
    reason = "an invalid repository-owned SHA-256 literal must fail at compile time"
)]
const fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("SHA-256 literal contains a non-hex digit"),
    }
}

#[allow(
    clippy::indexing_slicing,
    reason = "private callers provide the fixed 16-byte header region of a validated allocation"
)]
fn write_header(output: &mut [u8], crc: u32, version: u16, length_words: u16, uid: u32) {
    output[0..4].copy_from_slice(&crc.to_le_bytes());
    output[4..6].copy_from_slice(&version.to_le_bytes());
    output[6..8].copy_from_slice(&length_words.to_le_bytes());
    output[8..12].copy_from_slice(&uid.to_le_bytes());
    output[12] = CRC_UNCHECKED;
    output[13] = SECTION_UNKNOWN;
    output[14..16].copy_from_slice(&ROM_VERSION.to_le_bytes());
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::indexing_slicing,
    reason = "tests use fixed fixtures and expect success as part of each assertion"
)]
mod tests {
    use std::path::Path;

    use super::*;

    fn sample_code() -> Vec<u8> {
        (0_u8..37).collect()
    }

    fn load_fixture(path: &str) -> Option<Vec<u8>> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let path = root.join(path);
        path.exists()
            .then(|| std::fs::read(path).expect("read optional artifact fixture"))
    }

    fn assert_fixture(identity: FirmwareIdentity, path: &str) {
        let Some(image) = load_fixture(path) else {
            return;
        };
        let payload = identity
            .validate(&image)
            .expect("validate artifact identity");
        assert_eq!(payload.len(), identity.payload_size);
        assert_eq!(sha256(payload), identity.payload_sha256);
        assert_eq!(updater_crc32(payload), identity.payload_crc);
    }

    fn assert_corruption_rejected(identity: FirmwareIdentity, path: &str, offset: usize) {
        let Some(mut image) = load_fixture(path) else {
            return;
        };
        let byte = image
            .get_mut(offset)
            .expect("corruption offset inside fixture");
        *byte ^= 1;
        assert!(matches!(
            identity.validate(&image),
            Err(FirmwareIdentityError::ContainerMismatch { .. })
        ));
    }

    #[test]
    fn official_payload_constants() {
        assert_fixture(OFFICIAL_V449, "/tmp/slimblade-v449.bin");
    }

    #[test]
    fn descriptor_probe_payload_constants() {
        if load_fixture("/tmp/slimblade-v449-probe-bcd450.bin").is_some() {
            assert_fixture(
                V449_DESCRIPTOR_PROBE,
                "/tmp/slimblade-v449-probe-bcd450.bin",
            );
            return;
        }
        let Some(official) = load_fixture("/tmp/slimblade-v449.bin") else {
            return;
        };
        let probe = make_v449_descriptor_probe(&official).expect("construct descriptor probe");
        assert!(V449_DESCRIPTOR_PROBE.validate(&probe).is_ok());
    }

    #[test]
    fn recovery_carrier_payload_constants() {
        assert_fixture(
            RECOVERY_CARRIER,
            "firmware/recovery_carrier/build/DO_NOT_FLASH-stock-recovery-carrier.container.bin",
        );
    }

    #[test]
    fn recovery_carrier_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            RECOVERY_CARRIER,
            "firmware/recovery_carrier/build/DO_NOT_FLASH-stock-recovery-carrier.container.bin",
            0x21ac,
        );
    }

    #[test]
    fn reset_trampoline_payload_constants() {
        assert_fixture(
            RESET_TRAMPOLINE,
            "firmware/reset_trampoline/build/DO_NOT_FLASH-stock-reset-trampoline.container.bin",
        );
    }

    #[test]
    fn reset_trampoline_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            RESET_TRAMPOLINE,
            "firmware/reset_trampoline/build/DO_NOT_FLASH-stock-reset-trampoline.container.bin",
            0x2064,
        );
    }

    #[test]
    fn recovery_stub_payload_constants() {
        assert_fixture(
            RECOVERY_STUB,
            "firmware/recovery_stub/build/DO_NOT_FLASH-recovery-stub.container.bin",
        );
    }

    #[test]
    fn recovery_stub_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            RECOVERY_STUB,
            "firmware/recovery_stub/build/DO_NOT_FLASH-recovery-stub.container.bin",
            0x2064,
        );
    }

    #[test]
    fn startup_trampoline_payload_constants() {
        assert_fixture(
            STARTUP_TRAMPOLINE,
            "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
        );
    }

    #[test]
    fn startup_trampoline_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            STARTUP_TRAMPOLINE,
            "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
            0x22e4,
        );
    }

    #[test]
    fn recovery_guard_payload_constants() {
        assert_fixture(
            RECOVERY_GUARD,
            "firmware/recovery_guard/build/DO_NOT_FLASH-marker-first-guard-hang-probe.container.bin",
        );
    }

    #[test]
    fn recovery_guard_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            RECOVERY_GUARD,
            "firmware/recovery_guard/build/DO_NOT_FLASH-marker-first-guard-hang-probe.container.bin",
            0x21c4,
        );
    }

    #[test]
    fn stock_harness_payload_constants() {
        assert_fixture(
            STOCK_HARNESS,
            "firmware/bk3635-stock-harness/target/harness/DO_NOT_FLASH-stock-harness.container.bin",
        );
    }

    #[test]
    fn stock_harness_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            STOCK_HARNESS,
            "firmware/bk3635-stock-harness/target/harness/DO_NOT_FLASH-stock-harness.container.bin",
            0x21d6,
        );
    }

    #[test]
    fn late_marker_probe_payload_constants() {
        assert_fixture(
            LATE_MARKER_PROBE,
            "firmware/bk3635-stock-harness/target/late-marker/DO_NOT_FLASH-late-marker-probe.container.bin",
        );
    }

    #[test]
    fn late_marker_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            LATE_MARKER_PROBE,
            "firmware/bk3635-stock-harness/target/late-marker/DO_NOT_FLASH-late-marker-probe.container.bin",
            0x21be,
        );
    }

    #[test]
    fn experiment_entry_probe_payload_constants() {
        assert_fixture(
            EXPERIMENT_ENTRY_PROBE,
            "firmware/bk3635-stock-harness/target/experiment-entry/DO_NOT_FLASH-experiment-entry-probe.container.bin",
        );
    }

    #[test]
    fn experiment_entry_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            EXPERIMENT_ENTRY_PROBE,
            "firmware/bk3635-stock-harness/target/experiment-entry/DO_NOT_FLASH-experiment-entry-probe.container.bin",
            0x21c4,
        );
    }

    #[test]
    fn rust_response_probe_payload_constants() {
        assert_fixture(
            RUST_RESPONSE_PROBE,
            "firmware/bk3635-stock-harness/target/rust-response/DO_NOT_FLASH-rust-response-probe.container.bin",
        );
    }

    #[test]
    fn rust_response_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            RUST_RESPONSE_PROBE,
            "firmware/bk3635-stock-harness/target/rust-response/DO_NOT_FLASH-rust-response-probe.container.bin",
            0x22c4,
        );
    }

    #[test]
    fn post_init_hook_probe_payload_constants() {
        assert_fixture(
            POST_INIT_HOOK_PROBE,
            "firmware/bk3635-stock-harness/target/post-init-hook/DO_NOT_FLASH-post-init-hook-probe.container.bin",
        );
    }

    #[test]
    fn post_init_hook_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            POST_INIT_HOOK_PROBE,
            "firmware/bk3635-stock-harness/target/post-init-hook/DO_NOT_FLASH-post-init-hook-probe.container.bin",
            0x22c0,
        );
    }

    #[test]
    fn wired_loop_hook_probe_payload_constants() {
        assert_fixture(
            WIRED_LOOP_HOOK_PROBE,
            "firmware/bk3635-stock-harness/target/wired-loop-hook/DO_NOT_FLASH-wired-loop-hook-probe.container.bin",
        );
    }

    #[test]
    fn wired_loop_hook_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            WIRED_LOOP_HOOK_PROBE,
            "firmware/bk3635-stock-harness/target/wired-loop-hook/DO_NOT_FLASH-wired-loop-hook-probe.container.bin",
            0x22c0,
        );
    }

    #[test]
    fn active_loop_hook_probe_payload_constants() {
        assert_fixture(
            ACTIVE_LOOP_HOOK_PROBE,
            "firmware/bk3635-stock-harness/target/active-loop-hook/DO_NOT_FLASH-active-loop-hook-probe.container.bin",
        );
    }

    #[test]
    fn active_loop_hook_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            ACTIVE_LOOP_HOOK_PROBE,
            "firmware/bk3635-stock-harness/target/active-loop-hook/DO_NOT_FLASH-active-loop-hook-probe.container.bin",
            0x22a0,
        );
    }

    #[test]
    fn steady_loop_hook_probe_payload_constants() {
        assert_fixture(
            STEADY_LOOP_HOOK_PROBE,
            "firmware/bk3635-stock-harness/target/steady-loop-hook/DO_NOT_FLASH-steady-loop-hook-probe.container.bin",
        );
    }

    #[test]
    fn steady_loop_hook_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            STEADY_LOOP_HOOK_PROBE,
            "firmware/bk3635-stock-harness/target/steady-loop-hook/DO_NOT_FLASH-steady-loop-hook-probe.container.bin",
            0x22a0,
        );
    }

    #[test]
    fn dispatcher_return_hook_probe_payload_constants() {
        assert_fixture(
            DISPATCHER_RETURN_HOOK_PROBE,
            "firmware/bk3635-stock-harness/target/dispatcher-return-hook/DO_NOT_FLASH-dispatcher-return-hook-probe.container.bin",
        );
    }

    #[test]
    fn dispatcher_return_hook_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            DISPATCHER_RETURN_HOOK_PROBE,
            "firmware/bk3635-stock-harness/target/dispatcher-return-hook/DO_NOT_FLASH-dispatcher-return-hook-probe.container.bin",
            0x22a0,
        );
    }

    #[test]
    fn experiment_dispatch_guard_payload_constants() {
        assert_fixture(
            EXPERIMENT_DISPATCH_GUARD,
            "firmware/bk3635-stock-harness/target/experiment-dispatch-guard/DO_NOT_FLASH-experiment-dispatch-guard.container.bin",
        );
    }

    #[test]
    fn experiment_dispatch_guard_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            EXPERIMENT_DISPATCH_GUARD,
            "firmware/bk3635-stock-harness/target/experiment-dispatch-guard/DO_NOT_FLASH-experiment-dispatch-guard.container.bin",
            0x22c0,
        );
    }

    #[test]
    fn unsolicited_report_probe_payload_constants() {
        assert_fixture(
            UNSOLICITED_REPORT_PROBE,
            "firmware/bk3635-stock-harness/target/unsolicited-report-probe/DO_NOT_FLASH-unsolicited-report-probe.container.bin",
        );
    }

    #[test]
    fn unsolicited_report_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            UNSOLICITED_REPORT_PROBE,
            "firmware/bk3635-stock-harness/target/unsolicited-report-probe/DO_NOT_FLASH-unsolicited-report-probe.container.bin",
            0x22c0,
        );
    }

    #[test]
    fn input_diagnostics_payload_constants() {
        assert_fixture(
            INPUT_DIAGNOSTICS,
            "firmware/bk3635-stock-harness/target/input-diagnostics/DO_NOT_FLASH-input-diagnostics.container.bin",
        );
    }

    #[test]
    fn input_diagnostics_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            INPUT_DIAGNOSTICS,
            "firmware/bk3635-stock-harness/target/input-diagnostics/DO_NOT_FLASH-input-diagnostics.container.bin",
            0x22b4,
        );
    }

    #[test]
    fn paged_input_diagnostics_payload_constants() {
        assert_fixture(
            PAGED_INPUT_DIAGNOSTICS,
            "firmware/bk3635-stock-harness/target/paged-input-diagnostics/DO_NOT_FLASH-paged-input-diagnostics.container.bin",
        );
    }

    #[test]
    fn paged_input_diagnostics_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            PAGED_INPUT_DIAGNOSTICS,
            "firmware/bk3635-stock-harness/target/paged-input-diagnostics/DO_NOT_FLASH-paged-input-diagnostics.container.bin",
            0x22b4,
        );
    }

    #[test]
    fn sensor_shadow_diagnostics_payload_constants() {
        assert_fixture(
            SENSOR_SHADOW_DIAGNOSTICS,
            "firmware/bk3635-stock-harness/target/sensor-shadow-diagnostics/DO_NOT_FLASH-sensor-shadow-diagnostics.container.bin",
        );
    }

    #[test]
    fn sensor_shadow_diagnostics_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            SENSOR_SHADOW_DIAGNOSTICS,
            "firmware/bk3635-stock-harness/target/sensor-shadow-diagnostics/DO_NOT_FLASH-sensor-shadow-diagnostics.container.bin",
            0x1a798,
        );
    }

    #[test]
    fn custom_main_handoff_probe_payload_constants() {
        assert_fixture(
            CUSTOM_MAIN_HANDOFF_PROBE,
            "firmware/bk3635-stock-harness/target/custom-main-handoff/DO_NOT_FLASH-custom-main-handoff-probe.container.bin",
        );
    }

    #[test]
    fn custom_main_handoff_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            CUSTOM_MAIN_HANDOFF_PROBE,
            "firmware/bk3635-stock-harness/target/custom-main-handoff/DO_NOT_FLASH-custom-main-handoff-probe.container.bin",
            0x19c08,
        );
    }

    #[test]
    fn custom_main_usb_recovery_probe_payload_constants() {
        assert_fixture(
            CUSTOM_MAIN_USB_RECOVERY_PROBE,
            "firmware/bk3635-stock-harness/target/custom-main-usb-recovery/DO_NOT_FLASH-custom-main-usb-recovery-probe.container.bin",
        );
    }

    #[test]
    fn custom_main_usb_recovery_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            CUSTOM_MAIN_USB_RECOVERY_PROBE,
            "firmware/bk3635-stock-harness/target/custom-main-usb-recovery/DO_NOT_FLASH-custom-main-usb-recovery-probe.container.bin",
            0x22a2,
        );
    }

    #[test]
    fn custom_main_stream_transport_probe_payload_constants() {
        assert_fixture(
            CUSTOM_MAIN_STREAM_TRANSPORT_PROBE,
            "firmware/bk3635-stock-harness/target/custom-main-stream-transport/DO_NOT_FLASH-custom-main-stream-transport-probe.container.bin",
        );
    }

    #[test]
    fn custom_main_stream_transport_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            CUSTOM_MAIN_STREAM_TRANSPORT_PROBE,
            "firmware/bk3635-stock-harness/target/custom-main-stream-transport/DO_NOT_FLASH-custom-main-stream-transport-probe.container.bin",
            0x1c470,
        );
    }

    #[test]
    fn custom_main_sensor_stream_probe_payload_constants() {
        assert_fixture(
            CUSTOM_MAIN_SENSOR_STREAM_PROBE,
            "firmware/bk3635-stock-harness/target/custom-main-sensor-stream/DO_NOT_FLASH-custom-main-sensor-stream-probe.container.bin",
        );
    }

    #[test]
    fn custom_main_sensor_stream_probe_rejects_one_byte_corruption() {
        assert_corruption_rejected(
            CUSTOM_MAIN_SENSOR_STREAM_PROBE,
            "firmware/bk3635-stock-harness/target/custom-main-sensor-stream/DO_NOT_FLASH-custom-main-sensor-stream-probe.container.bin",
            0x1a798,
        );
    }

    #[test]
    fn reference_artifact_manifest_is_unique_and_complete() {
        assert_eq!(REFERENCE_ARTIFACTS.len(), 29);
        assert_eq!(
            REFERENCE_ARTIFACTS
                .iter()
                .filter(|artifact| artifact.container_sha256.is_some())
                .count(),
            24
        );
        for (index, artifact) in REFERENCE_ARTIFACTS.iter().enumerate() {
            assert_ne!(artifact.code_sha256, [0; 32]);
            assert!(
                REFERENCE_ARTIFACTS[index + 1..]
                    .iter()
                    .all(|other| artifact.name != other.name)
            );
        }
    }

    #[test]
    #[allow(
        clippy::too_many_lines,
        reason = "the flat fixture table keeps every artifact index and generated path reviewable"
    )]
    fn reference_artifact_hashes_match_available_builds() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let fixtures = [
            (
                0,
                "vendor/bk3633_sdk/SDK/projects/slimblade_wired/build/stock-startup-reference.bin",
                None,
            ),
            (
                1,
                "vendor/bk3633_sdk/SDK/projects/slimblade_wired/build/stock-startup-reference.interrupt-wrappers.bin",
                None,
            ),
            (
                2,
                "firmware/recovery_carrier/build/DO_NOT_FLASH-stock-recovery-carrier.code.bin",
                Some(
                    "firmware/recovery_carrier/build/DO_NOT_FLASH-stock-recovery-carrier.container.bin",
                ),
            ),
            (
                3,
                "firmware/reset_trampoline/build/DO_NOT_FLASH-stock-reset-trampoline.code.bin",
                Some(
                    "firmware/reset_trampoline/build/DO_NOT_FLASH-stock-reset-trampoline.container.bin",
                ),
            ),
            (
                4,
                "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.code.bin",
                Some(
                    "firmware/startup_trampoline/build/DO_NOT_FLASH-stock-startup-trampoline.container.bin",
                ),
            ),
            (
                5,
                "firmware/recovery_stub/build/DO_NOT_FLASH-recovery-stub.code.bin",
                Some("firmware/recovery_stub/build/DO_NOT_FLASH-recovery-stub.container.bin"),
            ),
            (
                6,
                "firmware/recovery_guard/build/DO_NOT_FLASH-marker-first-guard-hang-probe.code.bin",
                Some(
                    "firmware/recovery_guard/build/DO_NOT_FLASH-marker-first-guard-hang-probe.container.bin",
                ),
            ),
            (
                7,
                "firmware/bk3635-usb-probe/target/probe/DO_NOT_FLASH-usb-recovery-probe.code.bin",
                Some(
                    "firmware/bk3635-usb-probe/target/probe/DO_NOT_FLASH-usb-recovery-probe.container.bin",
                ),
            ),
            (
                8,
                "firmware/bk3635-stock-harness/target/harness/DO_NOT_FLASH-stock-harness.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/harness/DO_NOT_FLASH-stock-harness.container.bin",
                ),
            ),
            (
                9,
                "firmware/bk3635-stock-harness/target/late-marker/DO_NOT_FLASH-late-marker-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/late-marker/DO_NOT_FLASH-late-marker-probe.container.bin",
                ),
            ),
            (
                10,
                "firmware/bk3635-stock-harness/target/experiment-entry/DO_NOT_FLASH-experiment-entry-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/experiment-entry/DO_NOT_FLASH-experiment-entry-probe.container.bin",
                ),
            ),
            (
                11,
                "firmware/bk3635-stock-harness/target/rust-response/DO_NOT_FLASH-rust-response-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/rust-response/DO_NOT_FLASH-rust-response-probe.container.bin",
                ),
            ),
            (
                12,
                "firmware/bk3635-stock-harness/target/post-init-hook/DO_NOT_FLASH-post-init-hook-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/post-init-hook/DO_NOT_FLASH-post-init-hook-probe.container.bin",
                ),
            ),
            (
                13,
                "firmware/bk3635-stock-harness/target/wired-loop-hook/DO_NOT_FLASH-wired-loop-hook-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/wired-loop-hook/DO_NOT_FLASH-wired-loop-hook-probe.container.bin",
                ),
            ),
            (
                14,
                "firmware/bk3635-stock-harness/target/active-loop-hook/DO_NOT_FLASH-active-loop-hook-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/active-loop-hook/DO_NOT_FLASH-active-loop-hook-probe.container.bin",
                ),
            ),
            (
                15,
                "firmware/bk3635-stock-harness/target/steady-loop-hook/DO_NOT_FLASH-steady-loop-hook-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/steady-loop-hook/DO_NOT_FLASH-steady-loop-hook-probe.container.bin",
                ),
            ),
            (
                16,
                "firmware/bk3635-stock-harness/target/dispatcher-return-hook/DO_NOT_FLASH-dispatcher-return-hook-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/dispatcher-return-hook/DO_NOT_FLASH-dispatcher-return-hook-probe.container.bin",
                ),
            ),
            (
                17,
                "firmware/bk3635-stock-harness/target/experiment-dispatch-guard/DO_NOT_FLASH-experiment-dispatch-guard.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/experiment-dispatch-guard/DO_NOT_FLASH-experiment-dispatch-guard.container.bin",
                ),
            ),
            (
                18,
                "firmware/bk3635-stock-harness/target/input-diagnostics/DO_NOT_FLASH-input-diagnostics.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/input-diagnostics/DO_NOT_FLASH-input-diagnostics.container.bin",
                ),
            ),
            (
                19,
                "firmware/bk3635-stock-harness/target/paged-input-diagnostics/DO_NOT_FLASH-paged-input-diagnostics.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/paged-input-diagnostics/DO_NOT_FLASH-paged-input-diagnostics.container.bin",
                ),
            ),
            (
                20,
                "firmware/bk3635-stock-harness/target/sensor-shadow-diagnostics/DO_NOT_FLASH-sensor-shadow-diagnostics.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/sensor-shadow-diagnostics/DO_NOT_FLASH-sensor-shadow-diagnostics.container.bin",
                ),
            ),
            (
                21,
                "firmware/bk3635-stock-harness/target/unsolicited-report-probe/DO_NOT_FLASH-unsolicited-report-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/unsolicited-report-probe/DO_NOT_FLASH-unsolicited-report-probe.container.bin",
                ),
            ),
            (
                22,
                "firmware/bk3635-stock-harness/target/custom-main-handoff/DO_NOT_FLASH-custom-main-handoff-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/custom-main-handoff/DO_NOT_FLASH-custom-main-handoff-probe.container.bin",
                ),
            ),
            (
                23,
                "firmware/bk3635-stock-harness/target/custom-main-usb-recovery/DO_NOT_FLASH-custom-main-usb-recovery-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/custom-main-usb-recovery/DO_NOT_FLASH-custom-main-usb-recovery-probe.container.bin",
                ),
            ),
            (
                24,
                "firmware/bk3635-stock-harness/target/custom-main-stream-transport/DO_NOT_FLASH-custom-main-stream-transport-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/custom-main-stream-transport/DO_NOT_FLASH-custom-main-stream-transport-probe.container.bin",
                ),
            ),
            (
                25,
                "firmware/bk3635-stock-harness/target/custom-main-stream-transport/DO_NOT_FLASH-custom-main-stream-transport-probe.runtime.bin",
                None,
            ),
            (
                26,
                "firmware/bk3635-stock-harness/target/custom-main-sensor-stream/DO_NOT_FLASH-custom-main-sensor-stream-probe.injection.bin",
                Some(
                    "firmware/bk3635-stock-harness/target/custom-main-sensor-stream/DO_NOT_FLASH-custom-main-sensor-stream-probe.container.bin",
                ),
            ),
            (
                27,
                "firmware/bk3635-stock-harness/target/custom-main-sensor-stream/DO_NOT_FLASH-custom-main-sensor-stream-probe.runtime.bin",
                None,
            ),
            (
                28,
                "firmware/bk3635-stock-harness/target/custom-main-sensor-stream/DO_NOT_FLASH-custom-main-sensor-stream-probe.sensor.bin",
                None,
            ),
        ];
        for (identity_index, code_path, container_path) in fixtures {
            let identity = REFERENCE_ARTIFACTS[identity_index];
            let code_path = root.join(code_path);
            if !code_path.exists() {
                continue;
            }
            let code = std::fs::read(code_path).expect("read generated code artifact");
            assert!(identity.code_matches(&code), "{} code hash", identity.name);
            if let Some(container_path) = container_path {
                let container = std::fs::read(root.join(container_path))
                    .expect("read generated container artifact");
                assert_eq!(
                    identity.container_matches(&container),
                    Some(true),
                    "{} container hash",
                    identity.name
                );
            }
        }
    }

    #[test]
    fn application_container_round_trip() {
        let code = sample_code();
        let image = make_application_container(&code, 3, None).expect("valid synthetic code");
        let header = parse_header(&image, APPLICATION_HEADER_OFFSET).expect("application header");
        assert_eq!(header.uid, APPLICATION_UID);
        assert_eq!(header.end_offset(), Ok(image.len()));
        assert_eq!(header.calculate_crc(&image), Ok(header.crc));
        assert_eq!(header.crc, 0x45a5_e5cf);
        assert_eq!(
            sha256(&image),
            [
                0x1c, 0xcd, 0xaa, 0x0f, 0x99, 0xcc, 0xaa, 0xf4, 0x2e, 0x20, 0xd2, 0xd7, 0xff, 0x45,
                0xf4, 0xa9, 0x04, 0x1c, 0xed, 0x52, 0xbf, 0xf6, 0x16, 0xeb, 0x2c, 0x34, 0x8e, 0x96,
                0xe2, 0x8f, 0xcb, 0x55,
            ]
        );
        assert_eq!(
            &image[APPLICATION_CODE_OFFSET..APPLICATION_CODE_OFFSET + code.len()],
            &code
        );
        assert!(image.len().is_multiple_of(16));
    }

    #[test]
    fn empty_application_is_rejected() {
        assert_eq!(
            make_application_container(&[], 3, None),
            Err(ImageError::EmptyApplication)
        );
    }

    #[test]
    fn application_can_be_padded_to_official_geometry() {
        let code = sample_code();
        let image = make_application_container(&code, 3, Some(OFFICIAL_APPLICATION_END_OFFSET))
            .expect("valid official geometry");
        let header = parse_header(&image, APPLICATION_HEADER_OFFSET).expect("application header");
        assert_eq!(image.len(), OFFICIAL_V449_SIZE);
        assert_eq!(header.end_offset(), Ok(OFFICIAL_APPLICATION_END_OFFSET));
        assert_eq!(header.length_words, 0x7518);
        assert_eq!(header.calculate_crc(&image), Ok(header.crc));
        assert_eq!(header.crc, 0xa4cf_cc1f);
        assert_eq!(
            sha256(&image),
            [
                0x30, 0x13, 0x6a, 0x6f, 0x2c, 0xed, 0x9b, 0xe7, 0xc3, 0xba, 0x8a, 0xd5, 0x9e, 0x73,
                0xfb, 0x8b, 0x2c, 0x97, 0xbe, 0xed, 0x9b, 0xbc, 0xe3, 0x20, 0x36, 0xbb, 0xb7, 0x8a,
                0x02, 0x01, 0x2b, 0x2b,
            ]
        );
        assert_eq!(
            &image[APPLICATION_CODE_OFFSET..APPLICATION_CODE_OFFSET + code.len()],
            &code
        );
        assert!(
            image[APPLICATION_CODE_OFFSET + code.len()..]
                .iter()
                .all(|byte| *byte == 0xff)
        );
    }

    #[test]
    fn official_images_have_valid_known_headers_when_present() {
        for version in ["448", "449"] {
            let path = format!("/tmp/slimblade-v{version}.bin");
            if !Path::new(&path).exists() {
                continue;
            }
            let image = std::fs::read(path).expect("read temporary official image");
            let headers = inspect_headers(&image).expect("inspect official image");
            assert_eq!(headers.len(), 2);
            for header in headers {
                assert_eq!(header.crc_is_valid(&image), Ok(true));
            }
        }
    }

    #[test]
    fn v449_descriptor_probe_only_changes_metadata_and_bcd_device_when_present() {
        let path = Path::new("/tmp/slimblade-v449.bin");
        if !path.exists() {
            return;
        }
        let official = std::fs::read(path).expect("read temporary official v4.49 image");
        let probe = make_v449_descriptor_probe(&official).expect("construct descriptor probe");
        assert_eq!(probe.len(), official.len());
        assert_eq!(probe[V449_BCD_DEVICE_OFFSET], 0x50);
        assert_eq!(
            sha256(&probe),
            [
                0x99, 0x00, 0x79, 0xb8, 0xa7, 0x16, 0x68, 0xf0, 0xe1, 0x99, 0x63, 0xc7, 0x1a, 0x70,
                0xf8, 0xef, 0xac, 0x3f, 0x36, 0xe6, 0x9a, 0x21, 0x13, 0x3d, 0x60, 0xf9, 0x95, 0x1c,
                0xd8, 0x51, 0x90, 0x81,
            ]
        );
        for offset in [STACK_HEADER_OFFSET, APPLICATION_HEADER_OFFSET] {
            let header = parse_header(&probe, offset).expect("probe header");
            assert_eq!(header.crc_is_valid(&probe), Ok(true));
        }
        let changed: Vec<usize> = official
            .iter()
            .zip(&probe)
            .enumerate()
            .filter_map(|(index, (before, after))| (before != after).then_some(index))
            .collect();
        assert!(changed.contains(&V449_BCD_DEVICE_OFFSET));
        let stack_crc = STACK_HEADER_OFFSET..STACK_HEADER_OFFSET + 4;
        let application_crc = APPLICATION_HEADER_OFFSET..APPLICATION_HEADER_OFFSET + 4;
        assert!(changed.iter().all(|offset| {
            stack_crc.contains(offset)
                || application_crc.contains(offset)
                || *offset == V449_BCD_DEVICE_OFFSET
        }));
    }

    #[test]
    fn truncated_header_is_rejected() {
        assert_eq!(
            parse_header(&[0; HEADER_SIZE - 1], 0),
            Err(ImageError::HeaderOutOfBounds {
                offset: 0,
                image_length: HEADER_SIZE - 1,
            })
        );
    }

    #[test]
    fn header_region_beyond_image_is_rejected() {
        let mut image = [0_u8; HEADER_SIZE];
        image[6..8].copy_from_slice(&5_u16.to_le_bytes());
        let header = parse_header(&image, 0).expect("complete header");
        assert_eq!(
            header.calculate_crc(&image),
            Err(ImageError::RegionOutOfBounds {
                header_offset: 0,
                end: 20,
                image_length: 16,
            })
        );
    }

    #[test]
    fn header_region_before_payload_is_rejected_without_panicking() {
        let mut image = [0_u8; HEADER_SIZE];
        image[6..8].copy_from_slice(&1_u16.to_le_bytes());
        let header = parse_header(&image, 0).expect("complete header");
        assert_eq!(
            header.calculate_crc(&image),
            Err(ImageError::RegionBeforePayload {
                header_offset: 0,
                payload: 16,
                end: 4,
            })
        );
    }

    #[test]
    fn invalid_requested_geometry_is_rejected() {
        let code = sample_code();
        assert!(matches!(
            make_application_container(&code, 3, Some(APPLICATION_CODE_OFFSET + 32)),
            Err(ImageError::EndBeforeCode { .. })
        ));
        assert!(matches!(
            make_application_container(&code, 3, Some(APPLICATION_CODE_OFFSET + 49)),
            Err(ImageError::EndNotAligned { .. })
        ));
    }

    #[test]
    fn one_byte_payload_corruption_invalidates_crc() {
        let mut image = make_application_container(&sample_code(), 3, None)
            .expect("valid synthetic application");
        let header = parse_header(&image, APPLICATION_HEADER_OFFSET).expect("application header");
        image[APPLICATION_CODE_OFFSET] ^= 1;
        assert_eq!(header.crc_is_valid(&image), Ok(false));
    }
}
