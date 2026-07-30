use crate::deps;
use anyhow::Result;
use colored::*;
use serde::Serialize;
use std::path::Path;

// ── CycloneDX 1.5 Model ─────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxBom {
    #[serde(rename = "$schema")]
    schema: String,
    bom_format: String,
    spec_version: String,
    serial_number: String,
    version: u32,
    metadata: CycloneDxMetadata,
    components: Vec<CycloneDxComponent>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxMetadata {
    timestamp: String,
    tools: CycloneDxTools,
    properties: Vec<CycloneDxProperty>,
}

#[derive(Serialize)]
struct CycloneDxTools {
    components: Vec<CycloneDxTool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxTool {
    #[serde(rename = "type")]
    tool_type: String,
    name: String,
    version: String,
}

#[derive(Serialize)]
struct CycloneDxProperty {
    name: String,
    value: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxComponent {
    #[serde(rename = "type")]
    comp_type: String,
    name: String,
    version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    supplier: Option<CycloneDxSupplier>,
    #[serde(skip_serializing_if = "Option::is_none")]
    licenses: Option<Vec<CycloneDxLicense>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    external_references: Option<Vec<CycloneDxRef>>,
    properties: Vec<CycloneDxProperty>,
}

#[derive(Serialize)]
struct CycloneDxSupplier {
    name: String,
}

#[derive(Serialize)]
struct CycloneDxLicense {
    license: CycloneDxLicenseId,
}

#[derive(Serialize)]
struct CycloneDxLicenseId {
    id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CycloneDxRef {
    url: String,
    #[serde(rename = "type")]
    ref_type: String,
}

// ── SPDX 2.3 Model ──────────────────────────────────────────────────

#[derive(Serialize)]
struct SpdxDocument {
    #[serde(rename = "spdxVersion")]
    spdx_version: String,
    #[serde(rename = "dataLicense")]
    data_license: String,
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    #[serde(rename = "creationInfo")]
    creation_info: SpdxCreationInfo,
    #[serde(rename = "documentNamespace")]
    document_namespace: String,
    packages: Vec<SpdxPackage>,
    #[serde(rename = "documentDescribes")]
    document_describes: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxCreationInfo {
    creators: Vec<String>,
    created: String,
}

#[derive(Serialize)]
struct SpdxPackage {
    #[serde(rename = "SPDXID")]
    spdx_id: String,
    name: String,
    version_info: String,
    #[serde(rename = "supplier", skip_serializing_if = "Option::is_none")]
    supplier: Option<String>,
    #[serde(rename = "packageFileName", skip_serializing_if = "Option::is_none")]
    package_file_name: Option<String>,
    #[serde(rename = "downloadLocation")]
    download_location: String,
    #[serde(rename = "filesAnalyzed")]
    files_analyzed: bool,
    #[serde(rename = "licenseConcluded")]
    license_concluded: String,
    #[serde(rename = "licenseDeclared", skip_serializing_if = "Option::is_none")]
    license_declared: Option<String>,
    #[serde(rename = "copyrightText")]
    copyright_text: String,
    external_refs: Vec<SpdxExternalRef>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SpdxExternalRef {
    reference_category: String,
    reference_type: String,
    reference_locator: String,
}

// ── Ecosystem → PURL mapping ────────────────────────────────────────

pub fn ecosystem_to_purl_type(eco: &str) -> &str {
    match eco.to_lowercase().as_str() {
        "crates.io" => "cargo",
        "npm" => "npm",
        "pypi" => "pypi",
        "go" => "golang",
        "rubygems" => "gem",
        "packagist" => "composer",
        "pub" => "pub",
        _ => eco,
    }
}



/// Generate a CycloneDX 1.5 JSON SBOM
fn generate_cyclonedx(deps: &[deps::Dependency], project_name: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();

    let components: Vec<CycloneDxComponent> = deps
        .iter()
        .map(|d| {
            let purl = format!(
                "pkg:{}/{}@{}",
                ecosystem_to_purl_type(&d.ecosystem),
                d.name.to_lowercase(),
                d.version
            );

            CycloneDxComponent {
                comp_type: "library".to_string(),
                name: d.name.clone(),
                version: d.version.clone(),
                supplier: None,
                licenses: None,
                external_references: Some(vec![CycloneDxRef {
                    url: purl,
                    ref_type: "purl".to_string(),
                }]),
                properties: vec![
                    CycloneDxProperty {
                        name: "aquasecurity:trivy:Schema:ecosystem".to_string(),
                        value: d.ecosystem.clone(),
                    },
                    CycloneDxProperty {
                        name: "cipher-ai:manifest".to_string(),
                        value: d.manifest_file.to_string_lossy().to_string(),
                    },
                ],
            }
        })
        .collect();

    let bom = CycloneDxBom {
        schema: "https://cyclonedx.org/schema/bom-1.5.schema.json".to_string(),
        bom_format: "CycloneDX".to_string(),
        spec_version: "1.5".to_string(),
        serial_number: format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        version: 1,
        metadata: CycloneDxMetadata {
            timestamp: now,
            tools: CycloneDxTools {
                components: vec![CycloneDxTool {
                    tool_type: "application".to_string(),
                    name: "CipherAI".to_string(),
                    version: "0.1.0".to_string(),
                }],
            },
            properties: vec![CycloneDxProperty {
                name: "aquasecurity:trivy:Schema:project".to_string(),
                value: project_name.to_string(),
            }],
        },
        components,
    };

    serde_json::to_string_pretty(&bom).unwrap_or_else(|_| "{}".to_string())
}

/// Generate an SPDX 2.3 JSON SBOM
fn generate_spdx(deps: &[deps::Dependency], project_name: &str) -> String {
    let now = chrono::Utc::now().to_rfc3339();
    let namespace = format!("https://cipher-ai.dev/sbom/spdx/{}", uuid::Uuid::new_v4());

    let packages: Vec<SpdxPackage> = deps
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let purl = format!(
                "pkg:{}/{}@{}",
                ecosystem_to_purl_type(&d.ecosystem),
                d.name.to_lowercase(),
                d.version
            );

            SpdxPackage {
                spdx_id: format!("SPDXRef-Package-{}", i + 1),
                name: d.name.clone(),
                version_info: d.version.clone(),
                supplier: Some(format!("NOASSERTION")),
                package_file_name: None,
                download_location: format!("NOASSERTION"),
                files_analyzed: false,
                license_concluded: "NOASSERTION".to_string(),
                license_declared: None,
                copyright_text: "NOASSERTION".to_string(),
                external_refs: vec![SpdxExternalRef {
                    reference_category: "PACKAGE-MANAGER".to_string(),
                    reference_type: "purl".to_string(),
                    reference_locator: purl,
                }],
            }
        })
        .collect();

    let document = SpdxDocument {
        spdx_version: "SPDX-2.3".to_string(),
        data_license: "CC0-1.0".to_string(),
        spdx_id: "SPDXRef-DOCUMENT".to_string(),
        name: format!("{}/{}", project_name, "sbom"),
        creation_info: SpdxCreationInfo {
            creators: vec![
                "Tool: CipherAI-0.1.0".to_string(),
            ],
            created: now,
        },
        document_namespace: namespace,
        packages,
        document_describes: vec!["SPDXRef-DOCUMENT".to_string()],
    };

    serde_json::to_string_pretty(&document).unwrap_or_else(|_| "{}".to_string())
}

// ── External API ────────────────────────────────────────────────────

/// Run the `cipher-ai sbom` command
pub async fn run_sbom(
    project_path: &Path,
    format: &str,
    output: Option<&str>,
) -> Result<()> {
    let canonical_path = std::fs::canonicalize(project_path)?;
    let project_name = canonical_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "project".to_string());

    println!(
        "{} {}\n",
        "[PKG]".bright_blue().bold(),
        format!("Generating SBOM for {}...", canonical_path.display()).bold()
    );

    // Find and parse all manifests
    let manifests = deps::find_manifests(&canonical_path);

    if manifests.is_empty() {
        println!(
            "  {} No dependency manifests found. Cannot generate SBOM.",
            "[-]".yellow()
        );
        println!(
            "  Supported: Cargo.toml, package.json, requirements.txt, go.mod, Gemfile, composer.json, pubspec.yaml"
        );
        return Ok(());
    }

    println!(
        "  {} Found {} manifest file(s)",
        "[FILE]".cyan(),
        manifests.len().to_string().bold()
    );

    let mut all_deps: Vec<deps::Dependency> = Vec::new();

    for manifest in &manifests {
        match deps::parse_manifest(manifest) {
            Ok(deps_found) => {
                println!(
                    "  {} {} from {}",
                    "[OK]".green(),
                    format!("{} dependencies", deps_found.len()).bold(),
                    manifest.file_name().unwrap().to_string_lossy().yellow()
                );
                all_deps.extend(deps_found);
            }
            Err(e) => {
                eprintln!(
                    "  {} Failed to parse {}: {}",
                    "[!]".yellow(),
                    manifest.display(),
                    e
                );
            }
        }
    }

    // Deduplicate by (name, version)
    all_deps.sort_by(|a, b| a.ecosystem.cmp(&b.ecosystem).then(a.name.cmp(&b.name)));
    all_deps.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name) && a.ecosystem == b.ecosystem);

    if all_deps.is_empty() {
        println!("\n  {} No dependencies found.", "[-]".yellow());
        return Ok(());
    }

    println!(
        "  {} {} unique dependencies across {} ecosystems\n",
        "[*]".cyan(),
        all_deps.len().to_string().bold(),
        {
            let mut ecosystems: Vec<&str> = all_deps.iter().map(|d| d.ecosystem.as_str()).collect();
            ecosystems.sort();
            ecosystems.dedup();
            ecosystems.join(", ")
        }
    );

    // Generate the SBOM in the requested format
    let output_str = match format {
        "spdx" => generate_spdx(&all_deps, &project_name),
        _ => generate_cyclonedx(&all_deps, &project_name),
    };

    if let Some(out_path) = output {
        std::fs::write(out_path, &output_str)?;
        println!(
            "  {} {} SBOM written to {}",
            "[FILE]".cyan(),
            format.to_uppercase().yellow().bold(),
            out_path.yellow()
        );
        println!(
            "  {} {} dependencies documented",
            "[OK]".green(),
            all_deps.len().to_string().bold()
        );
    } else {
        println!("{}", output_str);
    }

    Ok(())
}

/// Collect SBOM dependency summary (count only, no output)
pub async fn collect_sbom_summary(project_path: &Path) -> Result<usize> {
    let canonical_path = std::fs::canonicalize(project_path)?;
    let manifests = deps::find_manifests(&canonical_path);

    if manifests.is_empty() {
        return Ok(0);
    }

    let mut all_deps: Vec<deps::Dependency> = Vec::new();
    for manifest in &manifests {
        if let Ok(deps_found) = deps::parse_manifest(manifest) {
            all_deps.extend(deps_found);
        }
    }

    // Deduplicate by (name, version)
    all_deps.sort_by(|a, b| a.ecosystem.cmp(&b.ecosystem).then(a.name.cmp(&b.name)));
    all_deps.dedup_by(|a, b| a.name.eq_ignore_ascii_case(&b.name) && a.ecosystem == b.ecosystem);

    Ok(all_deps.len())
}
