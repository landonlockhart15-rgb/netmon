# NetMon Roadmap

NetMon is currently an active personal project and usable local prototype. This roadmap separates what is already positioned as part of the project from what would make it easier for other people to trust, install, and use.

## Current focus

- Make the first-run experience predictable on Windows.
- Keep all sensitive runtime data local and gitignored.
- Improve documentation so a new user understands what NetMon does before installing it.
- Make the dashboard workflow easy to demonstrate with screenshots or a short GIF.

## Near-term improvements

### 1. Visual proof

- Add dashboard screenshots under `docs/screenshots/`.
- Add a short first-run GIF or video link.
- Show discovery, network status, DNS blocking, and AI explanation screens.

### 2. Install confidence

- Keep `docs/INSTALL.md` current.
- Add a simple release artifact when packaging stabilizes.
- Document known Windows permissions and admin requirements.
- Add a short uninstall/reset section.

### 3. Project quality signal

- Add a minimal CI workflow for syntax checks or smoke tests.
- Add tests around configuration loading and scan-target handling.
- Add issue templates for bugs and feature requests.
- Add a changelog once releases begin.

### 4. Security clarity

- Keep `SECURITY.md` clear about authorized use only.
- Document how sensitive data is stored locally.
- Make reversible firewall actions explicit in the UI and docs.
- Make optional cloud AI behavior explicit and opt-in.

## Longer-term ideas

- More robust device fingerprinting and naming.
- Better historical change views.
- Safer guided remediation workflows.
- Local-only investigation reports.
- Exportable snapshots for troubleshooting.
- More explicit module-level documentation.

## Not goals

- NetMon is not a cloud SOC platform.
- NetMon is not a tool for scanning networks without permission.
- NetMon is not meant to replace professional incident response tooling.
- NetMon should not require AI for core network visibility features.
