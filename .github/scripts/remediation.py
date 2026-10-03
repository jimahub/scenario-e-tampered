#!/usr/bin/env python3
"""修補追蹤（Stage 7 自動回饋）— 對應論文 ch3 §3.5.3（2026-09-29 新增）

Policy Gate 只決定「這次建置能不能部署」；本腳本負責「哪些漏洞要修、多久內修完」。
所有未列入有效例外的漏洞（含判定為 PASS 者）一律列入修補追蹤，不因放行而消失。

放在各 repository 的 .github/scripts/remediation.py，由 devsecops.yml 在 enforce 模式呼叫；
也可在本機對保存的 decision.json 重跑（不加 --create-issues 即只產生計畫、不呼叫 API）。

輸入
  decision.json                      policy_gate.py 的輸出（含逐筆 findings）
  .github/security/remediation-policy.json
                                     修補期限政策：各等級的天數。期限由組織依其弱點管理政策訂定
                                     （ISO/IEC 27001:2022 A.8.8）；實驗 repository 內的天數為示例值。
輸出
  remediation-plan.json              以「套件@版本」為單位（修補通常是升級套件）彙整：所含漏洞、
                                     最嚴重等級、修補期限、是否已阻擋部署；另記錄目標套件是否已列入追蹤。
  --create-issues                    以 GITHUB_TOKEN 建立追蹤 Issue（標籤 vuln-tracking）：
                                     同一套件@版本已有開啟中的 Issue 則不重複建立、保留原期限；
                                     本次掃描已不含的套件@版本，其開啟中的 Issue 自動關閉並留言。
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone

LABEL = 'vuln-tracking'
TITLE = '[漏洞追蹤] {}'
SEV_ORDER = ['KEV', 'Critical', 'High', 'Medium', 'Low']
GRYPE_SEV = {'critical': 'Critical', 'high': 'High', 'medium': 'Medium', 'low': 'Low', 'negligible': 'Low'}


def load_policy(path):
    p = json.load(open(path, encoding='utf-8'))
    days = p['days']
    for k in SEV_ORDER:
        if not isinstance(days.get(k), int) or days[k] < 0:
            raise SystemExit(f'remediation-policy.json：days.{k} 須為非負整數')
    if p.get('unknown') not in SEV_ORDER:
        raise SystemExit('remediation-policy.json：unknown 須為 ' + '／'.join(SEV_ORDER) + ' 之一')
    return p


def tier(f, policy):
    """修補等級：KEV 優先；其次依 Policy Gate 採用的 CVSS（NVD 優先）；CVSS 缺值改用 Grype 嚴重度，仍無則用 unknown。"""
    if f.get('kev'):
        return 'KEV'
    c = f.get('cvss')
    if c is not None:
        return 'Critical' if c >= 9.0 else 'High' if c >= 7.0 else 'Medium' if c >= 4.0 else 'Low'
    return GRYPE_SEV.get(str(f.get('severity', '')).lower(), policy['unknown'])


def build_plan(decision, policy, as_of, target_package=None):
    groups = {}
    for f in decision.get('findings', []):
        if f.get('exception'):
            continue
        key = f"{f['package']}@{f['version']}"
        g = groups.setdefault(key, {'package': key, 'vulns': []})
        g['vulns'].append({'id': f.get('cve') or f['reported_id'], 'reported_id': f['reported_id'],
                           'tier': tier(f, policy), 'cvss': f.get('cvss'), 'epss': f.get('epss'),
                           'kev': f.get('kev'), 'gate': f.get('decision')})
    items = []
    for g in groups.values():
        worst = min((v['tier'] for v in g['vulns']), key=SEV_ORDER.index)
        g['tier'] = worst
        g['due'] = (as_of + timedelta(days=policy['days'][worst])).isoformat()
        g['blocks_deploy'] = any(v['gate'] == 'BLOCK' for v in g['vulns'])
        g['vulns'].sort(key=lambda v: SEV_ORDER.index(v['tier']))
        items.append(g)
    items.sort(key=lambda g: (g['due'], SEV_ORDER.index(g['tier']), g['package']))
    plan = {'as_of': as_of.isoformat(), 'decision': decision.get('decision'),
            'policy_days': policy['days'], 'packages': len(items),
            'vulns': sum(len(g['vulns']) for g in items),
            'by_tier': {t: sum(g['tier'] == t for g in items) for t in SEV_ORDER},
            'excepted_ids': decision.get('excepted_ids', []), 'items': items}
    if target_package:
        plan['target_package'] = target_package
        plan['target_tracked'] = any(g['package'] == target_package for g in items)
    return plan


def api(method, url, token, body=None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body is not None else None,
                                 headers={'Authorization': f'Bearer {token}', 'Accept': 'application/vnd.github+json',
                                          'X-GitHub-Api-Version': '2022-11-28'})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read() or b'null')


def issue_body(g, run_url):
    rows = '\n'.join(f"| {v['id']} | {v['tier']} | {v['cvss'] if v['cvss'] is not None else '—'} | "
                     f"{v['epss'] if v['epss'] is not None else '—'} | {'是' if v['kev'] else '否'} | {v['gate']} |"
                     for v in g['vulns'])
    return (f"由 SBOM 驅動安全管線自動建立。\n\n"
            f"- 套件：`{g['package']}`\n- 修補等級：**{g['tier']}**\n- 修補期限：**{g['due']}**\n"
            f"- 本次建置是否因此被阻擋：{'是' if g['blocks_deploy'] else '否'}\n- 來源執行：{run_url}\n\n"
            f"| 漏洞 | 等級 | CVSS | EPSS | KEV | Policy Gate |\n|---|---|---|---|---|---|\n{rows}\n\n"
            "若確認為誤判或經核可接受風險，請於 `.github/security/exceptions.json` 新增例外（須含理由、核可者與到期日），"
            "勿直接關閉本 Issue；升級套件後，下次掃描不再出現此套件版本時會自動關閉。")


def sync_issues(plan, token, repo, run_url):
    base = f"https://api.github.com/repos/{repo}"
    open_issues, page = {}, 1
    while True:
        batch = api('GET', f"{base}/issues?labels={LABEL}&state=open&per_page=100&page={page}", token)
        for i in batch:
            if 'pull_request' not in i:
                open_issues[i['title']] = i
        if len(batch) < 100:
            break
        page += 1
    wanted = {TITLE.format(g['package']): g for g in plan['items']}
    log = {'created': [], 'existing': [], 'closed': []}
    for title, g in wanted.items():
        if title in open_issues:
            g['issue'] = open_issues[title]['html_url']
            log['existing'].append(g['package'])
            continue
        body = {'title': title, 'body': issue_body(g, run_url), 'labels': [LABEL, f"severity:{g['tier']}"]}
        try:
            i = api('POST', f"{base}/issues", token, body)
        except urllib.error.HTTPError as e:
            if e.code != 422:
                raise
            body.pop('labels')                     # 標籤無法建立時仍建立 Issue，標題可供辨識
            i = api('POST', f"{base}/issues", token, body)
        g['issue'] = i['html_url']
        log['created'].append(g['package'])
    for title, i in open_issues.items():
        if title.startswith(TITLE.format('')) and title not in wanted:
            api('POST', f"{base}/issues/{i['number']}/comments", token,
                {'body': f"本次掃描（{run_url}）已不含此套件版本的漏洞（已升級、移除或列入有效例外），自動關閉。"})
            api('PATCH', f"{base}/issues/{i['number']}", token, {'state': 'closed', 'state_reason': 'completed'})
            log['closed'].append(title[len(TITLE.format('')):])
    plan['issues'] = log
    return plan


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('decision_json')
    ap.add_argument('--policy', default='.github/security/remediation-policy.json')
    ap.add_argument('--out', default='remediation-plan.json')
    ap.add_argument('--as-of', type=date.fromisoformat, help='期限起算日（預設今日 UTC）')
    ap.add_argument('--target-package', help='情境植入套件（例 lodash@4.17.4），記錄是否已列入追蹤')
    ap.add_argument('--create-issues', action='store_true', help='以 GITHUB_TOKEN 同步追蹤 Issue')
    a = ap.parse_args()
    decision = json.load(open(a.decision_json, encoding='utf-8'))
    if decision.get('decision') not in ('PASS', 'WARN', 'BLOCK'):
        raise SystemExit(f"判定為 {decision.get('decision')}，掃描結果不可信，不產生修補計畫")
    plan = build_plan(decision, load_policy(a.policy), a.as_of or datetime.now(timezone.utc).date(), a.target_package)
    if a.create_issues:
        run_url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ['GITHUB_REPOSITORY']}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"
        plan = sync_issues(plan, os.environ['GITHUB_TOKEN'], os.environ['GITHUB_REPOSITORY'], run_url)
    json.dump(plan, open(a.out, 'w', encoding='utf-8'), ensure_ascii=False, indent=2)
    print(f"修補追蹤：{plan['packages']} 個套件版本、{plan['vulns']} 筆漏洞 {plan['by_tier']}"
          + (f"；Issue 新建 {len(plan['issues']['created'])}、既有 {len(plan['issues']['existing'])}、關閉 {len(plan['issues']['closed'])}"
             if 'issues' in plan else '') + (f"；目標套件已追蹤={plan['target_tracked']}" if 'target_tracked' in plan else ''),
          file=sys.stderr)


if __name__ == '__main__':
    main()
