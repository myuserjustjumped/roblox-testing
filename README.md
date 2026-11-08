# Roblox Automated Report Workflow (Test Repo)

> [!WARNING]
> This repository will definitely get nuked by GitHub soon.
> The code here is all made by an agentic Large Language Model (specific model i wont say.)

Test repository using GitHub Actions workflows to automatically report users on Roblox from a crawled users text file (`.txt`).

---

## Report Results (November 8)

*Note: Results were not tracked between November 3 and November 7 until November 8.*

Stats across all **30 Roblox accounts**:

| Metric | API Tag | Count |
| :--- | :--- | :--- |
| Successful | `violation` | 13,600 |
| Rejected | `no_violation` | 409,070 |
| Not answered yet | *(No tag)* | 83,714 |
| **Total Reports** | — | **506,384** |

---

## API Details

Uses the following Roblox endpoint to retrieve report status tags:

```text
https://usermoderation.roblox.com/v1/reports
```
