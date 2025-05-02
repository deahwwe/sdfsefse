# Bug Bounty Checklist 🛡️

---

## 1. Recon 🔍

### Subdomain Enumeration

- [Subdomain Finder](https://subdomainfinder.c99.nl/)
- Execute the following commands:

```bash
subfinder -d ucartz.com
assetfinder --subs-only ucartz.com
subzy run --targets all.txt  # Subdomain takeover tool
```

- [Dedupelist - حذف التكرار](https://dedupelist.com/):

```bash
cat domains.txt | httpx
```

...

## 32. Business Logic Errors

- Look for:
  - Same user registering twice
  - Applying coupon multiple times
  - Transferring funds without deduction
- Techniques:
  - Understand flow and test unexpected sequences
  - Automate repetitive actions
