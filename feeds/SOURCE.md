# EPSS／KEV 凍結快照

- 下載時間（UTC）：2026-09-28T12:28:50Z
- EPSS：https://epss.empiricalsecurity.com/epss_scores-current.csv.gz
  - 檔頭：`#model_version:v2026.06.15,score_date:2026-09-27T12:00:21Z`
  - SHA-256：`594eb987e2834512078c7f535bef85ebfeb31af538eaeb2802d7a4308e88b659`
- CISA KEV：https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  - catalogVersion 2026.09.27，dateReleased 2026-09-27T21:30:35.5521Z，1728 筆
  - SHA-256：`164f2f100c3a2a810745500f49a8dd9041d59f9542c0ac1316d71578f25cb80b`

Policy Gate（.github/scripts/policy_gate.py）只依本快照判定 EPSS 與 KEV；雜湊不符即判 FAIL。
