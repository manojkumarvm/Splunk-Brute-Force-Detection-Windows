# Brute-Force Detection in Windows with Splunk

## 📌 Project Overview

This project demonstrates the detection of potential brute-force login attacks against Windows systems using Splunk and Windows Security Event Logs.

The investigation focuses on identifying repeated failed authentication attempts and analyzing the associated usernames, source IP addresses, hosts, and timestamps.

The project uses Windows Security Event ID **5379**, which represents a failed logon attempt, to identify suspicious authentication activity.

---

## 🎯 Objectives

- Monitor Windows Security Event Logs using Splunk
- Identify repeated failed login attempts
- Detect potential brute-force authentication activity
- Analyze source IP addresses and targeted usernames
- Create Splunk searches for detecting suspicious authentication patterns
- Document investigation findings using screenshots and search queries

---

## 🛠️ Tools & Technologies

- Splunk
- Windows Security Event Logs
- Windows Event ID 5379
- SPL (Search Processing Language)
- Windows
- Cybersecurity / SIEM
- Brute-Force Detection

---

## 🔍 Detection Methodology

The detection process consists of the following steps:

1. Configure Windows Security Event Logs as a data source in Splunk.
2. Collect authentication events from the Windows system.
3. Search for failed login events using Event ID 5379.
4. Group failed authentication attempts by host and source information.
5. Count repeated failed login attempts.
6. Identify systems with multiple failed authentication attempts.
7. Investigate the source IP addresses and targeted accounts.
8. Document the results and identify potential brute-force activity.

---

## 📊 Windows Event ID Used

### Event ID 5379 – Failed Logon

Windows generates Event ID **4625** when a logon attempt fails.

Repeated occurrences of this event from the same source can indicate:

- Password guessing
- Brute-force attacks
- Credential attacks
- Misconfigured applications or services
- Unauthorized authentication attempts

Event ID 5379 by itself does not prove that an attack occurred. The events should be correlated with source IP addresses, usernames, timestamps, frequency, and other available security information.

---

## 🔎 Splunk Detection Query

The following SPL query searches for failed Windows logon attempts and identifies systems with repeated failures:

```spl
index=* 
sourcetype=WinEventLog:Security
EventCode=5379
| stats count as failed_attempts values(Account_Name) as usernames values(src_ip) as source_ips by host
| where failed_attempts >= 5
| sort - failed_attempts
