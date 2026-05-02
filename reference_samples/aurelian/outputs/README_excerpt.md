<img width="2752" alt="Aurelian — Open-Source Multi-Cloud Security Reconnaissance Framework for AWS, Azure, and GCP" src="docs/aurelian.webp" />
<h1 align="center">Aurelian</h1>

<p align="center">
  <strong>Open-source cloud security reconnaissance framework</strong><br/>
  Detect secrets, misconfigurations, public exposure, and privilege escalation paths across AWS, Azure, and GCP — from a single CLI.
</p>

<p align="center">
<a href="https://github.com/praetorian-inc/aurelian/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/praetorian-inc/aurelian/ci.yml?style=flat-square&label=build" alt="Aurelian CI Build Status"></a>
<a href="https://github.com/praetorian-inc/aurelian/releases"><img src="https://img.shields.io/github/v/release/praetorian-inc/aurelian?style=flat-square" alt="Aurelian Latest Release"></a>
<a href="https://opensource.org/licenses/Apache-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg?style=flat-square" alt="Apache 2.0 License"></a>
<a href="https://github.com/praetorian-inc/aurelian/stargazers"><img src="https://img.shields.io/github/stars/praetorian-inc/aurelian?style=flat-square" alt="GitHub Stars"></a>
<a href="https://goreportcard.com/report/github.com/praetorian-inc/aurelian"><img src="https://goreportcard.com/badge/github.com/praetorian-inc/aurelian?style=flat-square" alt="Go Report Card"></a>
</p>

<p align="center">
  <a href="#what-is-aurelian">What is Aurelian?</a> •
  <a href="#key-capabilities">Capabilities</a> •
  <a href="#installation">Installation</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#modules">Modules</a> •
  <a href="#documentation">Docs</a> •
  <a href="#faq">FAQ</a>
</p>

---

## What is Aurelian?

Aurelian is an open-source, multi-cloud security reconnaissance framework built in Go. It provides a single, unified command-line interface for cloud security assessments across Amazon Web Services (AWS), Microsoft Azure, and Google Cloud Platform (GCP).

Where other tools require you to learn separate workflows per cloud provider, Aurelian gives you **one command structure that works everywhere**: `aurelian [platform] recon [module]`. Each module encapsulates a complex, multi-step security workflow — resource enumeration, content extraction, secrets scanning, policy analysis, access evaluation — behind a single command.

Aurelian was built by the offensive security team at [Praetorian](https://www.praetorian.com), based on years of cloud penetration testing and red team engagements across hundreds of enterprise environments.

### Why Aurelian?

