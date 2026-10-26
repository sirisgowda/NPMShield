# NPMShield Review 2 tables (generated)

## Fused results

| Sample | Static | Dynamic | Fused | Verdict | Notes |
|---|---|---|---|---|---|
| 2024-09-20-duckc2-api-v1.0.0 | 100 | 50 | 70 | malicious |  |
| 2024-11-20-spid-gc-config-v5.1.4 | 50 | 35 | 41 | suspicious |  |
| 2025-03-25-epic-comment-rating-v1.0.0 | 0 | 0 | 0 | low | inert |
| 2025-05-25-blocks-nextjs-v9999.9999.10000 | 20 | 35 | 29 | low | static-clean / dynamic-flagged |
| 2025-06-19-mattermost-hardware-keyboard-v1.0.0 | 60 | 35 | 45 | suspicious |  |
| 2025-07-08-tailwind-base-theme-v1.0.0 | 20 | 35 | 29 | low | static-clean / dynamic-flagged |
| 2025-08-13-epc-node-web-client-v10.0.0 | 55 | 35 | 43 | suspicious |  |
| 2025-09-14-graphql-sequelize-teselagen-v5.3.8 | 40 | 100 | 80 | malicious | canary override |
| 2025-09-15-ng-imports-checker-v0.0.9 | 30 | 100 | 80 | malicious | canary override; static-clean / dynamic-flagged |
| 2025-11-17-calculator-40ed-v4.0.0 | 100 | 60 | 76 | malicious |  |
| 2025-12-18-npe-toolkit-server-deps-v1.0.0 | 0 | 0 | 0 | low | inert |
| 2026-01-28-monorepo-cop-v9.9.0 | 0 | 0 | 0 | low | inert |
| 2026-05-19-echarts-for-react-v3.0.7 | 0 | 0 | 0 | low | inert |
| axios-1.20.0 | 60 | 0 | 24 | low | static-flagged / dynamic-clean |
| chalk-6.0.1 | 0 | 0 | 0 | low | inert |
| debug-4.4.3 | 20 | 0 | 8 | low |  |
| express-5.2.1 | 15 | 0 | 6 | low |  |
| lodash-4.18.1 | 20 | 0 | 8 | low |  |

## Detection by method

| Method | Malicious flagged | Benign false positives |
|---|---|---|
| Static only | 6/13 (46%) | 1/5 (20%) |
| Dynamic only | 9/13 (69%) | 0/5 (0%) |
| Fused score (0.4 static + 0.6 dynamic, canary override) | 7/13 (54%) | 0/5 (0%) |
| Fused score + gap rule (dynamic-flagged gaps) | 9/13 (69%) | 0/5 (0%) |

## Attacker-controlled indicators (defanged, high confidence)

| Sample | Type | Value | Basis |
|---|---|---|---|
| 2024-11-20-spid-gc-config-v5.1.4 | url | hxxps://discord[.]com/api/webhooks/1306068586086793297/<redacted> | hardcoded-webhook |
| 2025-05-25-blocks-nextjs-v9999.9999.10000 | domain | geyybafvoogqfnn3xmadws172y8pwskh[.]oastify[.]com | observed |
| 2025-06-19-mattermost-hardware-keyboard-v1.0.0 | domain | bp4lqfam2mw2ha36kfd6ehcvemke84wt[.]oastify[.]com | observed |
| 2025-07-08-tailwind-base-theme-v1.0.0 | url | hxxps://ip-check-server[.]vercel[.]app/api/ip-check/208 | observed |
| 2025-07-08-tailwind-base-theme-v1.0.0 | domain | ip-check-server[.]vercel[.]app | observed |
| 2025-08-13-epc-node-web-client-v10.0.0 | domain | wvzo30h2[.]h1[.]ci | observed |
| 2025-08-13-epc-node-web-client-v10.0.0 | decoded_string | hxxps://wvzo30h2[.]h1[.]ci:8843/ | decoded |
| 2025-11-17-calculator-40ed-v4.0.0 | url | hxxps://vvucyl6abfnh5bv359d6kqiy4pahy9my[.]oastify[.]com/ | observed |
| 2025-11-17-calculator-40ed-v4.0.0 | domain | vvucyl6abfnh5bv359d6kqiy4pahy9my[.]oastify[.]com | observed |
| 2025-11-17-calculator-40ed-v4.0.0 | url | hxxps://vvucyl6abfnh5bv359d6kqiy4pahy9my[.]oastify[.]com/UFJFVFRZX05BTUU9IkRlYmlhbiBHTlUvTGludXggMTIgKGJvb2t3b3JtKSIKTkFNRT0iRGViaWFuIEdOVS9MaW51eCIKVkVSU0lPTl9JRD0iMTIiClZFUlNJT049IjEyIChib29rd29ybSkiClZFUlNJT05fQ09ERU5BTUU9Ym9va3dvcm0KSUQ9ZGViaWFuCkhPTUVfVVJMPSJodHRwczovL3d3dy5kZWJpYW4ub3JnLyIKU1VQUE9 | observed |
| 2025-11-17-calculator-40ed-v4.0.0 | domain | betsh1pquv6xorejopwm361en5txho5d[.]oastify[.]com | observed |

## Legitimate services contacted

| Sample | Services |
|---|---|
| 2024-09-20-duckc2-api-v1.0.0 | raw[.]githubusercontent[.]com |
| 2024-11-20-spid-gc-config-v5.1.4 | discord[.]com, ipinfo[.]io |
| 2025-09-14-graphql-sequelize-teselagen-v5.3.8 | 169[.]254[.]169[.]254:80, api[.]github[.]com, registry[.]npmjs[.]org, sts[.]us-east-1[.]amazonaws[.]com |
| 2025-09-15-ng-imports-checker-v0.0.9 | 169[.]254[.]169[.]254:80, api[.]github[.]com, registry[.]npmjs[.]org, sts[.]us-east-1[.]amazonaws[.]com |

## Low-confidence strings found in code (20 domains)

These are string literals inside package code (documentation links, target lists, proxy lists). They were not observed in the sandbox and need manual triage before being called indicators.

- anonymouse[.]org
- art-ws[.]org
- coccoc[.]com
- ddosvn[.]somee[.]com
- devlog[.]gregarius[.]net
- docs[.]sequelizejs[.]com
- downforeveryoneorjustme[.]com
- engadget[.]search[.]aol[.]com
- eu[.]battle[.]net
- filehippo[.]com
- funnymama[.]com
- gais[.]cs[.]ccu[.]edu[.]tw
- go[.]mail[.]ru
- grub[.]org
- help[.]baidu[.]com
- help[.]yahoo[.]com
- host-tracker[.]com
- ip-api[.]com
- itch[.]io
- npms[.]io
