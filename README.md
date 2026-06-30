# Container Security Scanner

![CI](https://github.com/basel5001/container-security-scanner/actions/workflows/test.yml/badge.svg)

A composite GitHub Action that scans container images for vulnerabilities using **Trivy** and **Grype**, and generates an SBOM with **Syft**.

## Features

- **Trivy** vulnerability scanning with severity filtering
- **Grype** vulnerability scanning for cross-validation
- **Syft** SBOM generation (SPDX or CycloneDX)
- Configurable failure thresholds
- Automatic artifact upload of scan results
- Markdown summary generation via bundled Python script

## Usage

```yaml
- name: Scan container
  uses: basel5001/container-security-scanner@v1
  with:
    image: myapp:latest
    severity: HIGH
```

### Full example

```yaml
name: Container Security

on:
  push:
    branches: [main]
  pull_request:

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Scan container image
        id: scan
        uses: basel5001/container-security-scanner@v1
        with:
          image: myapp:latest
          severity: HIGH
          fail-on-vuln: "true"
          generate-sbom: "true"
          sbom-format: spdx-json
          upload-results: "true"

      - name: Print results
        if: always()
        run: |
          echo "Trivy vulnerabilities: ${{ steps.scan.outputs.trivy-vulns }}"
          echo "Grype vulnerabilities: ${{ steps.scan.outputs.grype-vulns }}"
          echo "SBOM file: ${{ steps.scan.outputs.sbom-file }}"
```

### Without SBOM generation

```yaml
- name: Scan container (no SBOM)
  uses: basel5001/container-security-scanner@v1
  with:
    image: myapp:latest
    severity: CRITICAL
    generate-sbom: "false"
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `image` | Container image to scan (e.g., `nginx:latest`) | Yes | - |
| `severity` | Minimum severity to report (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) | No | `HIGH` |
| `fail-on-vuln` | Fail the workflow if vulnerabilities are found | No | `true` |
| `generate-sbom` | Generate SBOM with Syft | No | `true` |
| `sbom-format` | SBOM output format (`spdx-json`, `cyclonedx-json`) | No | `spdx-json` |
| `upload-results` | Upload scan results as artifacts | No | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `trivy-vulns` | Number of vulnerabilities found by Trivy |
| `grype-vulns` | Number of vulnerabilities found by Grype |
| `sbom-file` | Path to generated SBOM file |

## Summary Script

A bundled Python script (`src/summarize.py`) reads Trivy and Grype JSON output files and produces a Markdown summary report.

```bash
python3 src/summarize.py trivy-results.json grype-results.json
```

## Tools Used

| Tool | Purpose | Source |
|------|---------|--------|
| [Trivy](https://github.com/aquasecurity/trivy) | Vulnerability scanning | Aqua Security |
| [Grype](https://github.com/anchore/grype) | Vulnerability scanning | Anchore |
| [Syft](https://github.com/anchore/syft) | SBOM generation | Anchore |

## Development

### Run tests locally

```bash
pip install pytest
pytest tests/ -v
```

### Test the action locally with `act`

```bash
act -j scan-alpine
```

## License

[MIT](LICENSE)
