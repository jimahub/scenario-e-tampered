# scenario-e-tampered

Scenario E：SBOM 竄改

碩士論文〈SBOM 驅動的軟體供應鏈安全自動化：DevSecOps CI/CD 管線設計與實證評估〉第四章 §4.6 情境測試（實作正確性驗證）用 repository。

- 管線：`.github/workflows/devsecops.yml`（簽章端／驗證端兩個 job，先驗證後掃描，鎖定簽章身分）
- 只接受手動觸發（Actions → Run workflow），於正式實驗凍結工具版本後執行
- 情境 E 另含 tamper job（兩個 job 之間竄改 SBOM）與對照組 `attacker-resign.yml`

本 repository 刻意包含含已知漏洞的舊版套件，僅供研究用途，請勿用於正式環境。
