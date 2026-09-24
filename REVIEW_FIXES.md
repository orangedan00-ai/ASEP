# ASEP v2.9.5 Review Fixes

This patch keeps the 2.9.5 version and applies the requested review/regression fixes without adding new attack capabilities.

## Applied
- Fixed `lan-neighbor` topology source to use the ASEP host local IP, not the gateway.
- Kept `default-gateway` edges separate and deduplicated `(from,to)` pairs with `relations` provenance.
- Added `.detail-subtitle` styling.
- Made `ASEP_ROOT_APPROVAL_REQUIRED` configurable; default remains `true`.
- Removed duplicate `loadCapabilities()` definition.
- Aligned installer package coverage with the registered Kali tools; corrected ProjectDiscovery httpx to the Kali `httpx-toolkit` package/binary.
- Adjusted systemd `ProtectHome` generation so the opt-in self-modifying lifecycle is not silently blocked when the project is under `/home`.
- Added minimal HTTP Basic Auth enforcement for non-loopback service binds; localhost remains the default lab mode.
- Wired the existing tool inventory/plan/run/chain, passive target-path, adaptive analysis, replanning, Windows fingerprint, wireless chain, self-modifying apply, shell and sudo endpoints into the operator UI.

## Model review note
The prior review claimed `gpt-5.6-luna` was invalid. Current OpenAI documentation lists `gpt-5.6-luna` as the GPT-5.6 Luna model ID, so no downgrade/change was made to that setting.

## Validation
- `PYTHONPATH=. python3 -m unittest discover -s tests -v`: **46 tests, PASS**
- `node --check static/app.js`: **PASS**
- `python3 -m compileall -q app tests`: **PASS**
- `bash -n install.sh`: **PASS**
- Runtime smoke: **not executed in the build container because Flask is unavailable**. Run on Kali with `ASEP_REQUIRE_RUNTIME=1 ./validate_build.sh`.
