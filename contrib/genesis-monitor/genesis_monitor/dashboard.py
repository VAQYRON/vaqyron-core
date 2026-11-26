"""Dependency-free static HTML dashboard renderer; it opens no listener."""

from __future__ import annotations

import json
from typing import Any

from .protocol import ProtocolError


def _safe_json(value: Any) -> str:
    try:
        serialized = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False)
    except (TypeError, ValueError) as error:
        raise ProtocolError(f"dashboard data is not JSON-compatible: {error}") from error
    return (
        serialized.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


_HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>VAQYRON Genesis Monitor — Static Snapshot</title>
<style>
:root{color-scheme:dark;--bg:#10151d;--panel:#18212c;--muted:#9aabba;--line:#2b3948;--good:#73d69a;--warn:#f4c76b;--bad:#ff8585}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:#edf3f8;font:15px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1400px;margin:auto;padding:24px}h1{margin:0 0 4px;font-size:1.65rem}.sub,small{color:var(--muted)}
.banner{margin:18px 0;padding:12px 14px;border:1px solid var(--line);border-radius:8px;background:var(--panel)}
.machine{margin:16px 0;padding:16px;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
.machine-head{display:flex;gap:12px;align-items:baseline;flex-wrap:wrap}.machine-head h2{margin:0;font-size:1.2rem}
.badges{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}.badge{border:1px solid var(--line);border-radius:999px;padding:2px 10px}
.recent{color:var(--good)}.invalid,.found,.inconsistent{color:var(--bad)}.unknown,.stale{color:var(--warn)}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin:12px 0}
.metric{padding:8px;background:#111923;border-radius:6px}.metric b{display:block}.workers{width:100%;border-collapse:collapse;margin-top:10px}
th,td{text-align:left;vertical-align:top;padding:7px;border-bottom:1px solid var(--line)}th{color:var(--muted)}
code{overflow-wrap:anywhere}.empty{padding:20px;color:var(--muted)}
.alerts{border:1px solid var(--good);border-radius:8px;padding:12px;margin:16px 0;background:#15231e}
.verification{margin:10px 0;padding:10px;border:1px solid var(--line);border-radius:6px}
@media(max-width:700px){main{padding:12px}.workers{font-size:.85rem}}
</style>
</head>
<body><main>
<h1>VAQYRON Genesis Monitor</h1>
<div class="sub">Offline, read-only snapshot. Local machine identity binding is not authentication. Connectivity reflects accepted local ingestion, not authenticated remote-agent presence.</div>
<div id="generated" class="banner"></div><div id="alerts"></div><div id="machines"></div>
<script>
"use strict";
const DATA = __SNAPSHOT_JSON__;
const el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==null)n.textContent=String(text);if(cls)n.className=cls;return n;};
const fmt=(v)=>v===null||v===undefined?"unavailable":String(v);
const generated=document.getElementById("generated");
generated.textContent="Snapshot generated: "+fmt(DATA.generated_at);
const alertRoot=document.getElementById("alerts");
const alerts=Array.isArray(DATA.alerts)?DATA.alerts:[];
if(alerts.length){
 const panel=el("section",null,"alerts");panel.append(el("h2","Locally verified FOUND alerts"));
 for(const alert of alerts){
  const claim=alert.claim;
  const item=el("div",null,"verification");
  item.append(el("b","VERIFIED — "+alert.machine_id));
  item.append(el("div","Nonce "+fmt(claim.nonce)+" · block hash "+fmt(claim.block_hash)));
  item.append(el("div","PoW digest "+fmt(claim.pow_digest_raw)));
  item.append(el("small","Recorded "+fmt(alert.created_at)+" · local alert "+fmt(alert.alert_id)));
  panel.append(item);
 }
 alertRoot.append(panel);
}
const root=document.getElementById("machines");
if(!Array.isArray(DATA.machines)||DATA.machines.length===0){root.append(el("div","No registered machines.","empty"));}
for(const machine of DATA.machines){
 const section=el("section",null,"machine");
 const head=el("div",null,"machine-head");
 head.append(el("h2",machine.display_name),el("code",machine.machine_id));
 section.append(head);
 const badges=el("div",null,"badges");
 badges.append(el("span","Local ingestion: "+machine.ingestion_status,"badge "+machine.ingestion_status));
 badges.append(el("span","Search: "+machine.search_status,"badge "+machine.search_status));
 badges.append(el("span","Checkpoint: "+machine.checkpoint_age_status,"badge "+machine.checkpoint_age_status));
 section.append(badges);
 const metrics=el("div",null,"metrics");
 for(const [label,value] of [
  ["Last accepted local ingestion",machine.last_local_ingestion_at],
  ["Local ingestion age (s)",machine.local_ingestion_age_seconds],
  ["Search telemetry observed at",machine.telemetry_observed_at],
  ["Aggregate candidates",machine.log&&machine.log.aggregate_candidates],
  ["Aggregate candidates/s",machine.log&&machine.log.aggregate_candidates_per_second],
  ["Checkpoint age (s)",machine.checkpoint_age_seconds],
  ["Search result",machine.log&&machine.log.result],
  ["Current event sequence",machine.current_sequence]
 ]){const item=el("div",null,"metric");item.append(el("b",label),el("span",fmt(value)));metrics.append(item);}
 section.append(metrics);
 const workers=machine.log&&machine.log.workers;
 if(machine.log&&machine.log.worker_ranges_status!=="valid"){
  section.append(el("div","Worker ranges: "+fmt(machine.log.worker_ranges_status)+" — observed worker progress is not trusted.","empty"));
 }else if(Array.isArray(workers)&&workers.length){
  const table=el("table",null,"workers"),thead=el("thead"),header=el("tr");
  for(const title of ["Worker","Observed range","Latest observed nonce","Shared aggregate count at observation","Aggregate rate at observation","Progress timestamp"])header.append(el("th",title));
  thead.append(header);table.append(thead);const tbody=el("tbody");
  for(const worker of workers){const row=el("tr");for(const value of [
   worker.worker_index,fmt(worker.range_start)+".."+fmt(worker.range_end),worker.current_nonce,
   worker.shared_candidates_at_observation,worker.aggregate_candidates_per_second,worker.progress_timestamp
  ])row.append(el("td",fmt(value)));tbody.append(row);}
  table.append(tbody);section.append(table);
 }else{section.append(el("div","Worker progress unavailable.","empty"));}
 const verifications=Array.isArray(machine.found_verifications)?machine.found_verifications:[];
 const claims=[];
 if(machine.log&&machine.log.result==="FOUND"){
  claims.push({source:"log",candidate:machine.log.found_candidate});
 }
 if(machine.checkpoint&&machine.checkpoint.found){
  claims.push({source:"checkpoint",candidate:machine.checkpoint.found});
 }
 if(claims.length||verifications.length){
  section.append(el("h3","FOUND claims and independent verification"));
  for(const item of claims){
   const candidate=item.candidate;
   const nonce=candidate&&candidate.nonce;
   const hash=candidate&&(candidate.block_hash||candidate.header_hash);
   const digest=candidate&&candidate.pow_digest_raw;
   const matched=verifications.find(v=>v.claim.nonce===nonce&&v.claim.block_hash===hash&&v.claim.pow_digest_raw===digest);
   const status=matched?matched.status:"UNVERIFIED WORKER CLAIM";
   const card=el("div",null,"verification");
   card.append(el("b",status+" · "+item.source));
   card.append(el("div","Nonce "+fmt(nonce)+" · block hash "+fmt(hash)));
   card.append(el("div","PoW digest "+fmt(digest)));
   if(matched)card.append(el("small",matched.detail));
   section.append(card);
  }
  for(const verification of verifications){
   const card=el("div",null,"verification");
   card.append(el("b",verification.status+" · "+verification.source+" verification record"));
   card.append(el("div","Nonce "+fmt(verification.claim.nonce)+" · block hash "+fmt(verification.claim.block_hash)));
   card.append(el("div","PoW digest "+fmt(verification.claim.pow_digest_raw)));
   card.append(el("small",verification.detail+" · updated "+fmt(verification.updated_at)));
   section.append(card);
  }
 }
 const durableWorkers=machine.checkpoint&&machine.checkpoint.status==="valid"&&machine.checkpoint.workers;
 if(Array.isArray(durableWorkers)&&durableWorkers.length){
  section.append(el("h3","Durable checkpoint progress"));
  const table=el("table",null,"workers"),thead=el("thead"),header=el("tr");
  for(const title of ["Worker","Original range","Last definitely completed nonce"])header.append(el("th",title));
  thead.append(header);table.append(thead);const tbody=el("tbody");
  for(const worker of durableWorkers){const row=el("tr");for(const value of [
   worker.worker_index,fmt(worker.start_nonce)+".."+fmt(worker.end_nonce),worker.last_completed_nonce
  ])row.append(el("td",fmt(value)));tbody.append(row);}
  table.append(tbody);section.append(table);
 }
 root.append(section);
}
</script>
</main></body></html>
"""


def render_dashboard_html(snapshot: dict[str, Any]) -> str:
    if (
        not isinstance(snapshot, dict)
        or not {"generated_at", "machines"}.issubset(snapshot)
        or set(snapshot) - {"generated_at", "machines", "alerts"}
    ):
        raise ValueError("snapshot must contain generated_at and machines, with optional alerts")
    if not isinstance(snapshot["machines"], list):
        raise ValueError("snapshot machines must be an array")
    if "alerts" in snapshot and not isinstance(snapshot["alerts"], list):
        raise ValueError("snapshot alerts must be an array")
    return _HTML_TEMPLATE.replace("__SNAPSHOT_JSON__", _safe_json(snapshot))


def write_dashboard_snapshot(snapshot: dict[str, Any], output_path: str) -> None:
    """Write a static UTF-8 HTML snapshot; no server or network is created."""
    from pathlib import Path

    Path(output_path).write_text(render_dashboard_html(snapshot), encoding="utf-8", newline="")
