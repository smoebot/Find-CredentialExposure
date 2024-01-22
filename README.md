# Find-CredentialExposure
Powershell.  Search the Recorded Future Identity module API for exposed credentials

Provides information about Breaches and Dumps the credential is associated with

Sends a hash of the credential to the API, so this uses the Get-HashOfString function, with SHA1 instead of default SHA256

---

**Parameters**

_Email_

[Mandatory]

The Email credential to search for

---
**Examples**

```powershell
Find-CredentialExposure -Email kramer@monks.com
```
