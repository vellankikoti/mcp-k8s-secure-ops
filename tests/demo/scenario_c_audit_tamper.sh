#!/usr/bin/env bash
# scenario_c_audit_tamper.sh
# Operator cheat-sheet: tamper with an audit row; verify_chain detects it.
# Demonstrates the hash-chained audit ledger.
set -euo pipefail

echo "╔══════════════════════════════════════════════════════════╗"
echo "║   Scenario C — tamper-evident audit chain               ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "── PRE-REQUISITE ────────────────────────────────────────────"
echo "  Run scenarios A and B first so there are ≥3 audit rows."
echo ""

DB="${SECUREOPS_AUDIT_DB:-$HOME/.secureops/audit.db}"

echo "── CURRENT AUDIT LOG ────────────────────────────────────────"
sqlite3 "$DB" \
  'SELECT row_id, action_id, substr(prev_hash,1,16)||"...", substr(row_hash,1,16)||"..." FROM audit_rows ORDER BY row_id'
echo ""

echo "▶ CLAUDE DESKTOP PROMPT (step 1 — baseline verify):"
echo "  \"Verify the audit chain integrity.\""
echo ""
echo "── WHAT TO EXPECT — verify_chain (clean) ───────────────────"
echo "  Tool: verify_chain"
echo "  Result: ok=true, rows_checked=<N>, first_broken_row=null"
echo ""
echo "── CLI EQUIVALENT (rehearsal) ──────────────────────────────"
echo "  uv run --project \$(git rev-parse --show-toplevel) python - <<'PY'"
echo "  import asyncio, os"
echo "  from secureops_server.audit.ledger import AuditLedger"
echo "  async def main():"
echo "      l = AuditLedger(os.environ['SECUREOPS_AUDIT_DB'])"
echo "      r = await l.verify_chain()"
echo "      print(r)"
echo "  asyncio.run(main())"
echo "  PY"
echo ""
echo "── NOW TAMPER WITH ROW 2 ────────────────────────────────────"
echo "  (run this block manually on stage — it's the reveal moment)"
echo ""
echo "  sqlite3 $DB \\"
echo "    \"UPDATE audit_rows SET payload_json = json_patch(payload_json, '{\\\"tampered\\\": true}') WHERE row_id = 2\""
echo ""
echo "After running the above, press ENTER to continue..."
read -r _

echo ""
echo "── TAMPERED STATE ───────────────────────────────────────────"
sqlite3 "$DB" \
  "SELECT row_id, substr(payload_json,1,80)||'...' FROM audit_rows WHERE row_id = 2"
echo ""

echo "▶ CLAUDE DESKTOP PROMPT (step 2 — verify after tamper):"
echo "  \"Verify the audit chain again.\""
echo ""
echo "── WHAT TO EXPECT — verify_chain (broken) ──────────────────"
echo "  Tool: verify_chain"
echo "  Result: ok=false, first_broken_row=2"
echo "  Claude narrates: 'Row 2 hash does not match stored row_hash."
echo "   The audit chain is broken at row_id=2. Evidence of tampering.'"
echo ""
echo "── CLI EQUIVALENT ──────────────────────────────────────────"
echo "  sqlite3 $DB \\"
echo "    'SELECT row_id, prev_hash, row_hash, payload_json FROM audit_rows ORDER BY row_id' \\"
echo "    | python3 -c \\"
echo "    \"import sys, hashlib, json"
echo "     rows = [l.rstrip() for l in sys.stdin if l.strip()]"
echo "     print('Manual chain check — compare recomputed vs stored row_hash')\""
echo ""
echo "── EXPECTED OUTPUT SUMMARY ─────────────────────────────────"
echo "  verify_chain(clean):   ok=true"
echo "  verify_chain(tampered): ok=false, first_broken_row=2"
echo "  Audience takeaway: any mutation to payload_json breaks the SHA-256 chain."
echo ""
