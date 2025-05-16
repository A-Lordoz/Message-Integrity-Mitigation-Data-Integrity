# Message Authentication Code (MAC) Security Demonstration 
**Course**: Data Integrity and Authentication  
**Team Members**:  
- Ali Mohamed Oqab (2205077)  
- Rewan Ahmed Elwardany (2205218)  
- Ahmed Mahmoud Hassan (2205155)  
---
## Project Summary

This assignment covers two key areas:

- Exploiting weak MACs through **length extension attacks**
- Securing MACs with **HMAC using SHA-256**

It includes full documentation, working code, and a comparison of insecure and secure implementations.

---

## File Breakdown

| Filename           | Description                                         |
|--------------------|-----------------------------------------------------|
| `server.py`        | Simulates a vulnerable MAC system (MD5-based)       |
| `client.py`        | Launches a length extension attack                  |
| `secure_server.py` | Implements secure MAC using HMAC-SHA256             |

---

## Setup Instructions

1. Install dependencies:

```bash
pip install hashlib hmac python-dotenv
```
## Running the Code
### Start the Vulnerable Server

```bash
python server.py
```

Displays original message and corresponding MAC

### Run the Attack Script

```bash
python client.py
```

Paste the intercepted MAC

Watch the extended message get accepted by the server

### Test the Secure Server

```bash
python secure_server.py
```
Tampered messages are rejected

Invalid MACs are not accepted

## Secure Implementation Highlights
### Security Feature                	Applied Technique
Message Integrity	                HMAC with SHA-256
Input Hardening                 	Sanitizes message format and parameters
Timing Resistance               	Uses hmac.compare_digest() for MAC checks


## Attack Fix Comparison
Threat Type         	Insecure Method	                HMAC Countermeasure
Length Extension	    hash(secret + message)	        HMAC(key, message) using SHA-256
Hash Collisions	        MD5	                            SHA-256 in HMAC
Timing Disclosure	    == operator	                    compare_digest()