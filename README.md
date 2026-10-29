# Anonymized artifact: repository-borne prompt injection benchmark

Synthetic repository, toy-loop harness, gate harnesses, injection conditions, per-trial results and the analysis scripts for the submission. No real credentials, data or services are involved. All keys and callback values are fake canaries.

- code/: harness and attack scripts (bench3.py is the main harness; bench3_v4live.py is the version used for the live G4 rerun).
- results/A..D: per-trial jsonl for the G4 live rerun. results/oracle: functional oracle (oracle_g4.py), join and rescoring scripts, and output tables.
- results/readkey, results/adaptive32: read-key rerun and adaptive search trials.

Rebuild the gate-conditioned table: python3 results/oracle/snp_join.py <path to results> (reads oracle/oracle_rows.json and A..D/g4live_trials_*.jsonl).
Not yet included: canary listener, credential-gate helper, and the Aider, Gemini, Claude Code and ablation drivers. The paper states this.
Frozen after the submission deadline.
