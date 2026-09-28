#!/usr/bin/env python3
"""Policy Gate（演算法 3.1）— 對應論文 ch3 §3.5、§3.7.3、§3.9.4（2026-09-28 修訂版）

放在各實驗 repository 的 .github/scripts/policy_gate.py，由 devsecops.yml 的 Stage 6 呼叫；
也可在本機對保存的 grype-results.json 重跑（RQ4 的閾值與 CVSS 來源敏感度分析）。

輸入
  grype-results.json   Grype 預設模式輸出（不可加 --by-cve：Grype 0.111.0 的 --by-cve 會丟掉 NVD 紀錄，
                       CVSS 只剩 GitHub Advisory 的分數，例如 mongoose CVE-2022-2564 由 NVD 9.8 變成 7.0）
  feeds/epss.csv.gz    凍結的 FIRST EPSS 快照（全量）
  feeds/kev.json       凍結的 CISA KEV 目錄
  feeds/SHA256SUMS     上述兩檔的 SHA-256；不符即判 FAIL

判定（每筆漏洞，依序）
  KEV 命中                              → BLOCK（路徑①）
  CVSS 缺值                             → WARN（無法判斷嚴重度，交人工）
  CVSS ≥ 9.0 且 EPSS 缺值               → WARN（無法確認利用機率低，交人工）
  CVSS ≥ 9.0 且 EPSS ≥ 閾值             → BLOCK（路徑②）
  CVSS ≥ 9.0                            → WARN（路徑③）
  其他                                  → PASS（路徑④）
整份報告取最嚴重者（BLOCK > WARN > PASS）。

缺值原則：個別漏洞的資料缺值不得靜默放行（舊版把缺值當 0 分，屬 fail-open），
也不讓整條管線因個別缺值而無法運作（全擋會使真實專案每次都失敗）；
只有系統層級的輸入異常（掃描報告缺失或格式錯誤、快照缺失或雜湊不符）才判 FAIL。

CVSS 來源：NVD 紀錄的 Primary v3.x → NVD 紀錄任一 v3.x → GHSA 紀錄 v3.x → 任一版本 → 缺值。
另記錄 GHSA 的 v3.x 分數（cvss_ghsa），供 CVSS 來源敏感度分析（表 4.9g）。
"""
import argparse
import csv
import gzip
import hashlib
import io
import json
import os
import re
import sys

CVE_RE = re.compile(r'^CVE-\d{4}-\d{4,}$')
RANK = {'PASS': 0, 'WARN': 1, 'BLOCK': 2}


class InputError(Exception):
    """系統層級的輸入異常：整份判定為 FAIL。"""


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def check_sums(sums_path, files):
    try:
        lines = open(sums_path, encoding='utf-8').read().split('\n')
    except OSError as e:
        raise InputError(f'SHA256SUMS 無法讀取：{e}')
    want = {}
    for line in lines:
        if line.strip():
            digest, name = line.split(None, 1)
            want[os.path.basename(name.strip().lstrip('*'))] = digest.lower()
    got = {}
    for p in files:
        name = os.path.basename(p)
        if not os.path.exists(p):
            raise InputError(f'快照缺失：{p}')
        got[name] = sha256(p)
        if want.get(name) != got[name]:
            raise InputError(f'快照雜湊不符：{name}')
    return got


def load_epss(path):
    try:
        raw = gzip.open(path, 'rt', encoding='utf-8').read() if path.endswith('.gz') else open(path, encoding='utf-8').read()
    except OSError as e:
        raise InputError(f'EPSS 快照無法讀取：{e}')
    meta = {}
    lines = raw.split('\n')
    if lines and lines[0].startswith('#'):
        for kv in lines[0].lstrip('#').split(','):
            if ':' in kv:
                k, v = kv.split(':', 1)
                meta[k.strip()] = v.strip()
        lines = lines[1:]
    reader = csv.DictReader(io.StringIO('\n'.join(lines)))
    if not reader.fieldnames or not {'cve', 'epss'} <= set(reader.fieldnames):
        raise InputError('EPSS 快照缺少 cve、epss 欄位')
    scores = {r['cve']: float(r['epss']) for r in reader if r.get('cve')}
    if not scores:
        raise InputError('EPSS 快照是空的')
    return scores, meta


def load_kev(path):
    try:
        d = json.load(open(path, encoding='utf-8'))
    except (OSError, ValueError) as e:
        raise InputError(f'KEV 快照無法讀取：{e}')
    vulns = d.get('vulnerabilities') if isinstance(d, dict) else None
    if not isinstance(vulns, list) or not vulns:
        raise InputError('KEV 快照缺少 vulnerabilities')
    return {v['cveID'] for v in vulns if isinstance(v, dict) and CVE_RE.match(str(v.get('cveID', '')))}, \
        {'catalogVersion': d.get('catalogVersion'), 'dateReleased': d.get('dateReleased'), 'count': len(vulns)}


def scores(entries, version_prefix=None, kind=None):
    out = []
    for c in entries or []:
        if version_prefix and not str(c.get('version', '')).startswith(version_prefix):
            continue
        if kind and c.get('type') != kind:
            continue
        s = (c.get('metrics') or {}).get('baseScore')
        if isinstance(s, (int, float)):
            out.append(float(s))
    return out


def resolve_cvss(vuln, related):
    nvd = [r for r in related if str(r.get('namespace', '')).startswith('nvd')]
    nvd_cvss = [c for r in nvd for c in r.get('cvss') or []]
    for source, vals in (('nvd-primary-v3', scores(nvd_cvss, '3', 'Primary')),
                         ('nvd-v3', scores(nvd_cvss, '3')),
                         ('ghsa-v3', scores(vuln.get('cvss'), '3')),
                         ('any', scores(vuln.get('cvss')) + scores(nvd_cvss))):
        if vals:
            return max(vals), source
    return None, 'missing'


def classify(strategy, cvss, epss, kev, epss_t, cvss_t):
    """strategy 1＝純 CVSS、2＝雙因子（CVSS＋EPSS）、3＝三因子（KEV＋CVSS＋EPSS，即演算法 3.1）。"""
    if strategy == 3 and kev:
        return 'BLOCK', 'KEV'
    if cvss is None:
        return 'WARN', 'CVSS_MISSING'
    if cvss < cvss_t:
        return 'PASS', 'BELOW_THRESHOLD'
    if strategy == 1:
        return 'BLOCK', 'CVSS'
    if epss is None:
        return 'WARN', 'EPSS_MISSING'
    if epss >= epss_t:
        return 'BLOCK', 'CVSS+EPSS'
    return 'WARN', 'CVSS_EPSS_LOW'


def overall(labels):
    return max(labels, key=RANK.get) if labels else 'PASS'


def evaluate(grype_path, epss_path, kev_path, sums_path, epss_t=0.1, cvss_t=9.0):
    feed_sha = check_sums(sums_path, [epss_path, kev_path])
    epss_map, epss_meta = load_epss(epss_path)
    kev_set, kev_meta = load_kev(kev_path)
    try:
        report = json.load(open(grype_path, encoding='utf-8'))
    except (OSError, ValueError) as e:
        raise InputError(f'掃描報告無法讀取：{e}')
    matches = report.get('matches') if isinstance(report, dict) else None
    if not isinstance(matches, list):
        raise InputError('掃描報告缺少 matches（缺少掃描不等於沒有漏洞）')

    findings = []
    for m in matches:
        v = m.get('vulnerability') or {}
        related = m.get('relatedVulnerabilities') or []
        vid = str(v.get('id', ''))
        cves = sorted({vid} if CVE_RE.match(vid) else {r['id'] for r in related if CVE_RE.match(str(r.get('id', '')))})
        cvss, cvss_src = resolve_cvss(v, related)
        ghsa = scores(v.get('cvss'), '3')
        epss_vals = [epss_map[c] for c in cves if c in epss_map]
        f = {
            'reported_id': vid,
            'cve': cves[0] if len(cves) == 1 else None,
            'cve_candidates': cves,
            'cve_mapping': 'unique' if len(cves) == 1 else ('none' if not cves else 'ambiguous'),
            'package': (m.get('artifact') or {}).get('name'),
            'version': (m.get('artifact') or {}).get('version'),
            'severity': v.get('severity'),
            'cvss': cvss, 'cvss_source': cvss_src,
            'cvss_ghsa': max(ghsa) if ghsa else None,
            # 多個 CVE 對應時保守處理：EPSS 取最大、任一列於 KEV 即視為 KEV
            'epss': max(epss_vals) if epss_vals else None,
            'kev': any(c in kev_set for c in cves),
            # Grype 內建欄位僅供交叉核對，不參與判定
            'grype_epss': (v.get('epss') or [{}])[0].get('epss'),
            'grype_kev': bool(v.get('knownExploited')),
        }
        for s in (1, 2, 3):
            f[f's{s}'], f[f's{s}_reason'] = classify(s, f['cvss'], f['epss'], f['kev'], epss_t, cvss_t)
        f['decision'], f['reason'] = f['s3'], f['s3_reason']
        findings.append(f)

    label = lambda f: f['cve'] or f['reported_id']
    return {
        'decision': overall([f['decision'] for f in findings]),
        'strategies': {f's{s}': overall([f[f's{s}'] for f in findings]) for s in (1, 2, 3)},
        'thresholds': {'epss': epss_t, 'cvss': cvss_t},
        'total': len(findings),
        'block_ids': [label(f) for f in findings if f['decision'] == 'BLOCK'],
        'warn_ids': [label(f) for f in findings if f['decision'] == 'WARN'],
        'kev_ids': [label(f) for f in findings if f['kev']],
        'data_gaps': {
            'cvss_missing': sum(f['cvss'] is None for f in findings),
            'epss_missing': sum(f['epss'] is None for f in findings),
            'cve_unmapped': sum(f['cve_mapping'] == 'none' for f in findings),
            'cve_ambiguous': sum(f['cve_mapping'] == 'ambiguous' for f in findings),
        },
        'feeds': {'epss': epss_meta, 'kev': kev_meta, 'sha256': feed_sha},
        'grype_results_sha256': sha256(grype_path),
        'findings': findings,
    }


def scenario_check(result, expect, target_cve=None, target_reason=None, target_package=None):
    """情境判準（§3.9.5）：
    (1) 整份判定符合預期；(2) 目標 CVE 被偵測到，且判定與原因符合預期；
    (3) 歸因：使整份判定達到預期等級的漏洞全部來自植入套件（target_package，例 lodash@4.17.4），
        基底套件不得有任何漏洞達到該等級。植入套件本身的其他漏洞另行列出（例：lodash@4.17.4 同時含
        CVE-2019-10744 與 CVE-2026-4800，無法以換版本分開）。
    另記錄三策略在管線層級的判定，以區分 CVE 層級與管線層級的策略差異。"""
    if result['decision'] == 'FAIL':
        return {'ok': False, 'why': 'FAIL: ' + result.get('reason', '')}
    checks = {'decision': result['decision'] == expect}
    if target_cve:
        hits = [f for f in result['findings'] if target_cve in f['cve_candidates']]
        in_pkg = lambda f: target_package and f'{f["package"]}@{f["version"]}' == target_package
        causes = [f for f in result['findings'] if RANK[f['decision']] >= RANK[expect]]
        checks['target_found'] = bool(hits)
        checks['target_decision'] = any(f['decision'] == expect for f in hits)
        if target_reason:
            checks['target_reason'] = any(f['reason'] == target_reason for f in hits)
        outside = [f['cve'] or f['reported_id'] for f in causes
                   if target_cve not in f['cve_candidates'] and not in_pkg(f)]
        checks['causes_only_from_planted_package'] = not outside
        info = {'base_package_causes': outside,
                'planted_package_other_causes': [f['cve'] or f['reported_id'] for f in causes
                                                 if target_cve not in f['cve_candidates'] and in_pkg(f)]}
    else:
        info = {}
    return {'ok': all(checks.values()), 'expect': expect, 'target_cve': target_cve,
            'target_reason': target_reason, 'target_package': target_package, 'checks': checks, **info,
            'pipeline_level_strategies': result.get('strategies')}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('grype_json')
    ap.add_argument('--epss', default='feeds/epss.csv.gz')
    ap.add_argument('--kev', default='feeds/kev.json')
    ap.add_argument('--sums', default='feeds/SHA256SUMS')
    ap.add_argument('--epss-threshold', type=float, default=float(os.environ.get('EPSS_THRESHOLD', '0.1')))
    ap.add_argument('--cvss-critical', type=float, default=float(os.environ.get('CVSS_CRITICAL', '9.0')))
    ap.add_argument('--out', default='decision.json')
    ap.add_argument('--expect', help='情境預期判定（PASS／WARN／BLOCK）')
    ap.add_argument('--target-cve')
    ap.add_argument('--target-reason', help='例：KEV、CVSS+EPSS、CVSS_EPSS_LOW')
    ap.add_argument('--target-package', help='植入套件，例 lodash@4.17.4')
    ap.add_argument('--check-out', default='scenario-check.json')
    a = ap.parse_args()
    try:
        result = evaluate(a.grype_json, a.epss, a.kev, a.sums, a.epss_threshold, a.cvss_critical)
    except InputError as e:
        result = {'decision': 'FAIL', 'reason': str(e), 'findings': []}
    json.dump(result, open(a.out, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    if a.expect:
        chk = scenario_check(result, a.expect, a.target_cve, a.target_reason, a.target_package)
        json.dump(chk, open(a.check_out, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
        print(f"Scenario check: {'OK' if chk['ok'] else 'NOT OK'} {json.dumps({k: v for k, v in chk.items() if k not in ('expect', 'ok')}, ensure_ascii=False)}", file=sys.stderr)
    gaps = result.get('data_gaps', {})
    print(f"Policy Gate: {result['decision']}  BLOCK={len(result.get('block_ids', []))} "
          f"WARN={len(result.get('warn_ids', []))} KEV={len(result.get('kev_ids', []))} gaps={gaps}"
          + (f"  reason={result['reason']}" if result['decision'] == 'FAIL' else ''), file=sys.stderr)
    print(result['decision'])


if __name__ == '__main__':
    main()
