# Catálogo de Agentes — 0ctopus

Flota de **307 agentes** de pentesting, hacking y seguridad para Claude Code. El **orquestador** (`pentest-orchestrator`) coordina y delega; los especialistas ejecutan; `report-writer` consolida los reportes en `output/`.

> ⚠️ Todos trabajan **solo sobre objetivos autorizados**. Ver `CLAUDE.md` para las reglas de alcance y autorización.

## Coordinación y especialistas base (6)
`network-specialist` · `pentest-orchestrator` · `recon-specialist` · `report-writer` · `web-specialist` · `wireless-specialist`

## AD (2)
`active-directory-auditor` · `kerberos-attack-tester`

## AD/Network (1)
`ldap-enumerator`

## API y microservicios (7)
`api-gateway-tester` · `grpc-security` · `microservices-authz` · `openapi-swagger-auditor` · `service-mesh-security` · `soap-xml-webservice` · `webhook-security`

## Active Directory y Windows (9)
`adcs-tester` · `applocker-wdac-bypass` · `credential-dumping-detection` · `dpapi-tester` · `gpo-abuse-auditor` · `ntlm-relay-tester` · `uac-privilege-audit` · `windows-persistence-audit` · `wmi-dcom-tester`

## Autenticacion avanzada (7)
`account-takeover-tester` · `mfa-bypass-tester` · `oauth-device-flow-tester` · `password-reset-tester` · `scim-provisioning-tester` · `sso-federation-tester` · `webauthn-fido2-tester`

## Auth (3)
`oauth2-oidc-tester` · `saml-sso-tester` · `session-management-tester`

## Automotriz (5)
`can-bus-tester` · `infotainment-ivi-tester` · `keyless-entry-tester` · `obd2-tester` · `telematics-tcu-tester`

## Avionica, maritimo y espacio (5)
`acars-tester` · `adsb-aviation-tester` · `ais-maritime-tester` · `nmea-marine-tester` · `satellite-comms-tester`

## Bases de datos (7)
`elasticsearch-security-auditor` · `mongodb-security-auditor` · `mssql-security-auditor` · `mysql-security-auditor` · `oracle-db-auditor` · `postgres-security-auditor` · `redis-security-auditor`

## Blockchain y Web3 (8)
`blockchain-node-security` · `bridge-security-auditor` · `defi-protocol-auditor` · `mev-analysis` · `nft-security-tester` · `rust-contract-auditor` · `solidity-contract-auditor` · `wallet-security-tester`

## Cloud (6)
`aws-security-auditor` · `azure-security-auditor` · `cloud-iam-analyzer` · `gcp-security-auditor` · `s3-storage-bucket-hunter` · `serverless-function-tester`

## Cloud profundo (14)
`aws-cloudfront-security` · `aws-cognito-security` · `aws-ec2-security` · `aws-lambda-security` · `aws-rds-security` · `azure-aks-security` · `azure-functions-security` · `azure-keyvault-security` · `azure-storage-security` · `cloud-secrets-exposure` · `gcp-bigquery-security` · `gcp-cloud-functions` · `gcp-gke-security` · `multicloud-posture`

## Cloud/Container (1)
`kubernetes-security-auditor`

## Cloud/DevSecOps (1)
`terraform-iac-scanner`

## Compliance y gobierno (7)
`gdpr-privacy-auditor` · `iso27001-auditor` · `nist-csf-auditor` · `owasp-asvs-auditor` · `pci-dss-auditor` · `soc2-auditor` · `threat-modeling-stride`

## Container (1)
`docker-container-auditor`

## Contenedores y orquestacion (5)
`container-escape-tester` · `container-registry-security` · `containerd-runtime-security` · `helm-chart-security` · `openshift-security`

## Criptografia avanzada (4)
`crypto-implementation-review` · `key-management-auditor` · `password-storage-auditor` · `pki-certificate-auditor`

## Crypto/Network (1)
`tls-ssl-deep-tester`

## DevSecOps (1)
`secrets-supplychain-scanner`

## DevSecOps y CI/CD (9)
`ansible-security` · `cloudformation-security` · `dependency-confusion` · `github-actions-security` · `gitlab-ci-security` · `gitops-argocd-security` · `jenkins-security` · `pulumi-cdk-security` · `sbom-generator`

## Dispositivos medicos (3)
`dicom-pacs-tester` · `hl7-fhir-tester` · `medical-device-security`

## Email y comunicaciones (3)
`collab-webhook-tester` · `exchange-security-tester` · `smtp-advanced-tester`

## Fintech y POS (4)
`atm-security-auditor` · `emv-card-tester` · `payment-gateway-pci` · `pos-terminal-tester`

## Forense y DFIR (10)
`disk-forensics` · `incident-response` · `log-siem-analysis` · `malware-dynamic-sandbox` · `memory-forensics` · `mobile-cloud-forensics` · `network-forensics` · `sigma-detection-engineer` · `threat-hunting` · `yara-rule-engineer`

## Gaming y VR/AR (3)
`game-client-rev` · `game-server-tester` · `vr-ar-headset-tester`

## IA, ML y LLM (9)
`adversarial-ml-tester` · `ai-agent-security` · `ai-model-extraction` · `ai-privacy-pii` · `data-poisoning-tester` · `llm-jailbreak-testing` · `llm-prompt-injection` · `mlops-pipeline-security` · `rag-security-tester`

## ICS SCADA y OT (9)
`bacnet-tester` · `dnp3-tester` · `ethernetip-cip-tester` · `hmi-scada-security` · `iec61850-tester` · `modbus-tester` · `opc-ua-tester` · `plc-security-auditor` · `s7comm-siemens-tester`

## IoT (1)
`iot-firmware-analyzer`

## IoT y hardware (14)
`bootloader-security` · `fault-injection-assessment` · `firmware-emulation` · `hardware-sidechannel-assessment` · `hsm-auditor` · `i2c-bus-tester` · `iot-cloud-integration` · `jtag-swd-tester` · `rtos-security` · `secure-boot-auditor` · `spi-flash-dump` · `tpm-auditor` · `uart-debug-tester` · `usb-attack-surface`

## Linux (1)
`linux-privesc-auditor`

## Linux y Unix (5)
`kernel-module-auditor` · `pam-config-auditor` · `selinux-apparmor-auditor` · `sudo-polkit-auditor` · `systemd-security-auditor`

## Malware/DFIR (1)
`malware-static-analyzer`

## Mensajeria y colas (4)
`amqp-nats-tester` · `kafka-security-auditor` · `mqtt-broker-tester` · `rabbitmq-security-auditor`

## Mobile (8)
`android-apk-analyzer` · `flutter-app-analyzer` · `ios-ipa-analyzer` · `mobile-deeplink-tester` · `mobile-frida-dynamic` · `mobile-insecure-storage` · `mobile-mitm-network` · `react-native-analyzer`

## Mobile avanzado (12)
`android-intent-fuzzer` · `android-native-lib` · `android-runtime-tester` · `flutter-reactnative-deep` · `ios-keychain-storage` · `ios-runtime-tester` · `ios-url-scheme-tester` · `mobile-app-updates` · `mobile-biometric-tester` · `mobile-payments-nfc` · `mobile-pinning-bypass` · `mobile-webview-tester`

## Network (5)
`network-deep-mapper` · `network-segmentation-tester` · `smb-enumerator` · `snmp-enumerator` · `vpn-security-tester`

## Network/Email (1)
`email-security-tester`

## OSINT (2)
`metadata-document-analyzer` · `osint-corporate-recon`

## Perifericos (3)
`mfp-scanner-tester` · `network-printer-tester` · `usb-peripheral-audit`

## Red avanzada (12)
`dhcp-attacks-tester` · `dns-rebinding-tester` · `dns-tunneling-tester` · `firewall-waf-tester` · `ftp-tftp-tester` · `ipv6-security-tester` · `layer2-mitm-tester` · `network-dos-resilience` · `ntp-security-tester` · `proxy-socks-tester` · `rdp-security-tester` · `ssh-hardening-auditor`

## Red team y post-explotacion (7)
`edr-detection-testing` · `exfiltration-simulation` · `lateral-movement-auditor` · `persistence-auditor` · `physical-social-assessment` · `privilege-escalation-chains` · `red-team-planner`

## Reversing (1)
`binary-reverse-engineer`

## Reversing/AppSec (1)
`fuzzing-specialist`

## Secure code y SAST (5)
`code-review-security` · `sast-backend-languages` · `sast-c-cpp` · `sast-dotnet` · `sast-web-languages`

## Social (1)
`phishing-campaign-simulator`

## Streaming (5)
`drm-security-analyzer` · `hls-dash-streaming-tester` · `media-cdn-tester` · `rtmp-rtsp-stream-tester` · `video-watermark-analyzer`

## Streaming y medios avanzado (6)
`audio-streaming-tester` · `chromecast-dlna-tester` · `hdcp-hdmi-tester` · `iptv-middleware-tester` · `smart-tv-app-tester` · `widevine-cdm-analyzer`

## Threat intel y OSINT (5)
`brand-domain-monitor` · `dark-web-monitor` · `leak-credential-monitor` · `social-media-osint` · `threat-intel-analyst`

## Vigilancia y CCTV (3)
`access-control-physical` · `ip-camera-onvif-tester` · `nvr-dvr-tester`

## VoIP y telecom (4)
`asterisk-freepbx-tester` · `sip-pbx-tester` · `sms-gateway-tester` · `voip-fraud-detection`

## Wearables y smart home (4)
`home-automation-hub-tester` · `smart-lock-tester` · `smart-speaker-tester` · `smartwatch-tester`

## Web (9)
`access-control-idor` · `cors-misconfig-tester` · `csrf-tester` · `file-upload-tester` · `sql-injection-specialist` · `ssrf-specialist` · `web-owasp-top10` · `xss-specialist` · `xxe-injection-tester`

## Web avanzado (14)
`business-logic-tester` · `clickjacking-ui-redress` · `command-injection` · `http-request-smuggling` · `ldap-injection` · `nosql-injection` · `open-redirect` · `prototype-pollution` · `race-condition-tester` · `rate-limit-bypass` · `server-side-template-injection` · `web-cache-poisoning` · `web3-frontend-security` · `websocket-security`

## Web/API (2)
`api-rest-security` · `graphql-security`

## Web/Auth (1)
`jwt-token-tester`

## Windows (1)
`windows-privesc-auditor`

## Wireless y RF avanzado (12)
`ble-mesh-tester` · `bluetooth-classic-tester` · `gps-gnss-spoofing-detection` · `gsm-2g-tester` · `lorawan-tester` · `lte-5g-tester` · `wifi-eviltwin-detection` · `wifi-pmkid-tester` · `wifi-wpa3-tester` · `wifi-wps-tester` · `zigbee-tester` · `zwave-tester`

## Wireless/RF (3)
`bluetooth-ble-tester` · `rfid-nfc-tester` · `sdr-rf-analyzer`

## macOS (3)
`macos-gatekeeper-tester` · `macos-persistence-audit` · `macos-tcc-auditor`

---
**Total: 307 agentes.** Skills de dominio en `.claude/skills/`.