# Security Policy

NetMon is a local-first defensive network visibility project.

## Authorized use only

Use NetMon only on networks, devices, and systems that you own or are explicitly authorized to test.

Do not use NetMon to scan, probe, attack, disrupt, or collect information from third-party networks or devices without permission.

## Sensitive local data

NetMon may generate or reference sensitive local data, including:

- `.env` files
- local databases
- packet captures
- DNS blocklist caches
- logs
- uploaded wordlists or security-lab files
- notification credentials
- API keys for optional AI providers

These files should remain local and should not be committed to the repository.

## API keys and credentials

Keep API keys and credentials in local environment variables or a gitignored `.env` file. Never commit real keys, passwords, tokens, or recovery secrets.

The public repository should contain only safe examples such as `.env.example` with blank or placeholder values.

## AI-provider behavior

NetMon can use local AI models through Ollama. Optional cloud provider integrations should be treated as opt-in because they may send prompt content to an external provider.

Before enabling a cloud provider, review what data is included in prompts and whether that is acceptable for your environment.

## Reporting a vulnerability

If you find a security issue in this project, open a private report if GitHub security advisories are enabled for the repository. If not, open a minimal issue that describes the affected area without posting exploitable details publicly.

Useful reports include:

- what component is affected
- the expected behavior
- the observed behavior
- steps to reproduce on an owned test network
- relevant logs with secrets removed

## Scope

Good-faith defensive testing, documentation fixes, and safe hardening suggestions are welcome.

Requests to make unauthorized scanning, exploitation, persistence, credential theft, stealth, or evasion easier are out of scope.
