[<img src="https://cloudsploit.com/images/logos/cloudsploit_by_aqua_2021.png" height="130">](https://cloud.aquasec.com/signup)

[![Build Status](https://travis-ci.com/aquasecurity/cloudsploit.svg?branch=master)](https://travis-ci.com/aquasecurity/cloudsploit)

CloudSploit by Aqua - Cloud Security Scans
=================

[<img src="docs/console.png">](https://cloud.aquasec.com/signup)

## Quick Start
### Generic
```
$ git clone https://github.com/aquasecurity/cloudsploit.git
$ cd cloudsploit
$ npm install
$ ./index.js -h
```

### Docker
```
$ git clone https://github.com/aquasecurity/cloudsploit.git
$ cd cloudsploit
$ docker build . -t cloudsploit:0.0.1
$ docker run cloudsploit:0.0.1 -h
$ docker run -e AWS_ACCESS_KEY_ID=XX -e AWS_SECRET_ACCESS_KEY=YY cloudsploit:0.0.1 --compliance=pci
```

## Documentation
* [Background](#background)
* [Deployment Options](#deployment-options)
  + [Self-Hosted](#self-hosted)
  + [Hosted at Aqua Wave](#hosted-at-aqua-wave)
* [Installation](#installation)
* [Configuration](#configuration)
  + [Amazon Web Services](docs/aws.md#cloud-provider-configuration)
  + [Microsoft Azure](docs/azure.md#cloud-provider-configuration)
  + [Google Cloud Platform](docs/gcp.md#cloud-provider-configuration)
  + [Oracle Cloud Infrastructure](docs/oracle.md#cloud-provider-configuration)
  + [CloudSploit Config File](#cloudsploit-config-file)
  + [Credential Files](#credential-files)
    + [AWS](#aws)
    + [Azure](#azure)
    + [GCP](#gcp)
    + [Oracle OCI](#oracle-oci)
  + [Environment Variables](#environment-variables)
