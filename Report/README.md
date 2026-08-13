# BOTSv3 Security Investigation

## 1. Introduction
## 2. SOC Roles & Incident Handling Reflection
## 3. Installation & Data Preparation
## 4. Guided Investigation
   ### Question 1
   ### Question 2
   ### Question 3
   ### Question 4
   ### Question 5
   ### Question 6
## 5. Conclusion
## 6. Video Presentation
## 7. References
Bianco, D. (2024) Hypothesis-driven cryptominer hunting with Peak, Splunk. Available at: https://www.splunk.com/en_us/blog/security/hypothesis-driven-cryptominer-hunting-with-peak.html (Accessed: 11 August 2026). 

Security updates detail (no date) Broadcom Inc. Available at: https://www.broadcom.com/support/security-center/securityupdates/detail?fid=sep&pvid=sep14_2_2&suid=CIDS_Enterprise_SEP_14_2_2-SU224-20231019.061&year=2023 (Accessed: 11 August 2026). 

Splunk (no date) Splunk/botsv3: Splunk boss of the SOC version 3 dataset., GitHub. Available at: https://github.com/splunk/botsv3 (Accessed: 10 August 2026). 

‘Event order functions’, *Splunk Search Reference* (no date) Splunk. Available at: https://help.splunk.com/ (Accessed: 11 August 2026). 


## Appendix A – Investigation Evidence

This appendix contains the supporting evidence collected during the installation, data-validation and investigation stages. Screenshots are referenced from the main report where relevant rather than being embedded throughout the main body.

### Figure A1 – Splunk Enterprise Setup

Successful startup of Splunk Enterprise on the Ubuntu virtual machine. The terminal output confirms that the Splunk web service became available on TCP port `8000`.

![Figure A1 - Splunk Enterprise Setup](evidence/SplunkSetup.png)



### Figure A2 – BOTSv3 Dataset Integrity Verification

Verification of the downloaded `botsv3_data_set.tgz` archive against the MD5 checksum published by Splunk. The result of `botsv3_data_set.tgz: OK` confirms that the downloaded archive matched the expected checksum prior to extraction.

![Figure A2 - BOTSv3 Dataset Integrity Verification](evidence/ConfirmBotnet.png)



### Figure A3 – BOTSv3 Dataset Validation

Splunk search used to validate that the BOTSv3 dataset had been successfully loaded. The search returned approximately **1.94 million events across 107 sourcetypes**, confirming that the index was available for investigation.

![Figure A3 - BOTSv3 Dataset Validation](evidence/BotsValidation.png)



### Figure A4 – Question 1: Processor Utilisation

Splunk results showing the first occurrence of processes reaching 100% CPU utilisation after excluding the `Idle` and `_Total` performance counters. The results identify `chrome#5` as the second process to reach 100% CPU utilisation.

![Figure A4 - Question 1 Processor Utilisation](evidence/Q1Proof.png)



### Figure A5 – Question 2: Cryptocurrency-Mining Endpoint

DNS telemetry showing CoinHive-related activity. The results were correlated with the processor-utilisation findings from Question 1 to identify `BSTOLL-L` as the endpoint showing evidence of successful cryptocurrency-mining activity.

![Figure A5 - Question 2 Cryptocurrency Mining Endpoint](evidence/Q2Proof.png)



### Figure A6 – Questions 3 and 4: SEP Signature ID and Attack Name

Splunk analysis of Symantec Endpoint Protection telemetry using the `first()` event-order function. The result identifies the first-seen coin-miner threat signature as `30358` and associates it with `Web Attack: JSCoinminer Download 8`.

This single result provides evidence for both **Question 3** and **Question 4**.

![Figure A6 - Questions 3 and 4 SEP Signature](evidence/Q3and4Proof.png)



### Figure A7 – Question 5: Threat Severity

Official Broadcom/Symantec security-update information showing `Web Attack: JSCoinminer Download 8` with a vendor-assigned severity of **Medium**.

![Figure A7 - Question 5 Threat Severity](evidence/Q5Proof.png)



### Figure A8 – Question 6: Successful Threat Prevention

Symantec Endpoint Protection results showing **23 blocked events** associated with signature `30358` on endpoint `BTUN-L`. The result explicitly records the action as `attack blocked`, providing evidence that the endpoint-security control successfully prevented the cryptocurrency-mining threat.

![Figure A8 - Question 6 Threat Prevention](evidence/Q6Proof.png)