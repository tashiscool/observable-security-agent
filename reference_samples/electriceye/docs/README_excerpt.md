# ElectricEye

<p align="center">
  <img src="./screenshots/logo.svg" width="420" height="420">
</p>

ElectricEye is a multi-cloud, multi-SaaS Python CLI tool for Asset Management, Security Posture Management & Attack Surface Monitoring supporting 100s of services and evaluations to harden your CSP & SaaS environments with controls mapped to over 20 industry, regulatory, and best practice controls frameworks.

![VulnScan](https://github.com/jonrau1/ElectricEye/actions/workflows/sbom-vulns.yml/badge.svg)  ![CodeQL](https://github.com/jonrau1/ElectricEye/actions/workflows/codeql-analysis.yml/badge.svg) ![EcrBuild](https://github.com/jonrau1/ElectricEye/actions/workflows/push-ecr-public.yml/badge.svg) ![OcrBuild](https://github.com/jonrau1/ElectricEye/actions/workflows/push-ocr-public.yml/badge.svg) ![DockerHubBuild](https://github.com/jonrau1/ElectricEye/actions/workflows/push-docker-hub.yml/badge.svg)

<p>
  <a href="https://hub.docker.com/r/electriceye/electriceye"><img alt="Docker Pulls" src="https://img.shields.io/docker/pulls/electriceye/electriceye"></a>
  <a href="https://hub.docker.com/r/electriceye/electriceye"><img alt="Docker" src="https://img.shields.io/docker/image-size/electriceye/electriceye"></a>
  <a href="https://github.com/jonrau1/ElectricEye"><img alt="Repo size" src="https://img.shields.io/github/repo-size/jonrau1/ElectricEye"></a>
  <a href="https://github.com/jonrau1/ElectricEye/issues"><img alt="Issues" src="https://img.shields.io/github/issues/jonrau1/ElectricEye"></a>
  <a href="https://github.com/jonrau1/ElectricEye"><img alt="Contributors" src="https://img.shields.io/github/contributors-anon/jonrau1/ElectricEye"></a>
  <a href="https://github.com/jonrau1/ElectricEye"><img alt="License" src="https://img.shields.io/github/license/jonrau1/ElectricEye"></a>
</p>

<p align="center">
  <a href="https://gallery.ecr.aws/t4o3u7t2/electriceye"><img width="150" height="40" padding="5" alt="AWS ECR Gallery" src="https://user-images.githubusercontent.com/3985464/151531396-b6535a68-c907-44eb-95a1-a09508178616.png"></a>
  <a href="https://hub.docker.com/r/electriceye/electriceye"><img width="150" height="40" padding="5" alt="Docker Hub" src="https://www.unixtutorial.org/images/software/docker-hub.png"></a>
</p>

***Up here in space***<br/>
***I'm looking down on you***<br/>
***My lasers trace***<br/>
***Everything you do***<br/>
<sub>*Judas Priest, 1982*</sub>

## Table of Contents

- [Workflow](#workflow)
- [Quick Run Down](#quick-run-down-running-running)
- [Configuring ElectricEye](#configuring-electriceye)
- [Cloud Asset Management](#cloud-asset-management-cam)
- [Supported Services and Checks](#supported-services-and-checks)
- [ElectricEye on Docker](#electriceye-on-docker)
- [Outputs](./docs/outputs/OUTPUTS.md)
- [Contributing](#contributing)
- [FAQ](#faq)
- [Developer & Testing Guide](./docs/new_checks/DEVELOPER_GUIDE.md)
- [Repository Security](#repository-security)
- [License](#license)

## Workflow

![Architecture](./screenshots/electrice_eye_architecture.jpg)

## Quick Run Down :running: :running:

- ElectricEye is a Python CLI tool that offers cross-Account, cross-Region, multi-Cloud & SaaS Asset Management, Security Posture Management, and Attack Surface Monitoring capabilities across [AWS, all Partitions supported!](https://aws.amazon.com/), [GCP](https://cloud.google.com/), [Oracle Cloud Infrastructure (OCI)](https://www.oracle.com/cloud/), [ServiceNow](https://www.servicenow.com/), [Microsoft 365 Enterprise (*M365*)](https://www.microsoft.com/en-us/microsoft-365/compare-microsoft-365-enterprise-plans), [Salesforce (*SFDC*)](https://help.salesforce.com/s), and [Azure](https://portal.azure.com/).

- ElectricEye offers over *1000* Checks against security, resilience, performance, and financial best practices across more than 100 CSP & SaaS services, including atypical services not supported by CSP/SaaS-native asset management tools/views or mainstream CSPM & CNAPP tools.

- Every single Check is mapped to over 20 controls frameworks covering general best practices, regulatory, industry-specific, and legal frameworks such as NIST CSF, AICPA TSCs (for SOC 2), the HIPAA Security Rule, NIST 800-171 Rev. 2, CMMC V2.0, European Central Bank's CROE Section 2, PCI-DSS V4.0, CIS Foundations Benchmarks, and more!

- Multi-faceted Attack Surface Monitoring uses tools such as VirusTotal, Nmap, Shodan.io, Detect-Secrets, and CISA's KEV to locate assets indexed on the internet, find exposed services, locate exploitable vulnerabilities, and malicious packages in artifact repositories, respectively.

- Outputs to [AWS Security Hub](https://aws.amazon.com/security-hub/), the [Open Cyber Security Framework (OCSF)](https://github.com/ocsf/) [V1.1.0](https://schema.ocsf.io/1.1.0/?extensions=) in JSON, [AWS DocumentDB](https://aws.amazon.com/documentdb/), JSON, CSV, HTML Reports, [MongoDB](https://www.mongodb.com/), [Amazon SQS](https://aws.amazon.com/sqs/), [PostgreSQL](https://www.postgresql.org/), [Slack](https://slack.com/) (via Slack App Bots), and [FireMon Cloud Defense](https://www.firemon.com/introducing-disruptops/).

ElectricEye's core concept is the **Auditor** which are sets of Python scripts that run **Checks** per Service dedicated to a specific SaaS vendor or public cloud service provider called an **Assessment Target**.  You can run an entire Assessment Target, a specific Auditor, or a specific Check within an Auditor. After ElectricEye is done with evaluations, it supports over a dozen types of **Outputs** ranging from an HTML executive report to AWS DocumentDB clusters - you can run multiple Outputs as you see fit.

ElectricEye also uses utilizes other tools such as [Shodan.io](https://www.shodan.io/), [Yelp's `detect-secrets`](https://pypi.org/project/detect-secrets/), [VirusTotal](https://www.virustotal.com/gui/home/upload), the [United States Cyber and Infrastructure Security Agency (CISA)](https://www.cisa.gov/) [Known Exploited Vulnerability (KEV)](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) Catalog, and [NMAP](https://nmap.org/) for carrying out its Checks and enriching their findings.

1. First, clone this repository and install the requirements using `pip3`: `pip3 install -r requirements.txt`.

2. If you are evaluating anything other than your local AWS Account, modify the [TOML configuration](./eeauditor/external_providers.toml)  located in `ElectricEye/eeauditor/external_providers.toml`, or provide a path to your own with with `--toml-path`. The TOML file specifies multi-account, mulit-region, credential, and output specifics.

3. Finally, run the Controller to learn about the various Checks, Auditors, Assessment Targets, and Outputs.

```
python3 eeauditor/controller.py --help
Usage: controller.py [OPTIONS]

Options:
  -t, --target-provider [AWS|Azure|OCI|GCP|Servicenow|M365|Salesforce|Snowflake]
                                  Public cloud or SaaS assessment target,
                                  ensure that any -a or -c arg maps to your
                                  target provider to avoid any errors. e.g.,
                                  -t AWS -a Amazon_APGIW_Auditor
  -a, --auditor-name TEXT         Specify which Auditor you want to run by
                                  using its name NOT INCLUDING .py. . Use the
                                  --list-checks arg to receive a list.
                                  Defaults to ALL Auditors
  -c, --check-name TEXT           A specific Check in a specific Auditor you
                                  want to run, this correlates to the function
                                  name. Use the --list-checks arg to receive a
                                  list. Defaults to ALL Checks
  -d, --delay INTEGER             Time in seconds to sleep between Auditors
