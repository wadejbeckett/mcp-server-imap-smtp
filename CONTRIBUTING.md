# Contributing

Contributions are welcome: bug reports, fixes, documentation and support for more mail server set-ups.

- **Before you start.** Open an issue first for anything larger than a small fix, so the approach can be agreed.
- **Set up.** `uv venv && uv pip install -e ".[dev]"`, then `.venv/bin/pytest`. Every change needs tests, and the suite must pass. Integration tests against a real mailbox are opt-in: `pytest -m integration`, with credentials from the environment (see docs/RUNNING.md).
- **Style.** Keep the style of the surrounding code: small functions, plain names, and comments that explain why rather than what.
- **Security.** The connector holds other people's mail passwords. Changes to sign-in, sealing, tokens or the mail server binding get extra review. Never log message content, recipients, tokens or passwords.
- **No company specifics in the code.** Operator names, hosts and limits belong in the configuration.
- **Licensing.** By contributing, you agree that your contribution is licensed under the GNU Affero General Public License, version 3 or later (AGPL-3.0-or-later). New source files start with `# SPDX-License-Identifier: AGPL-3.0-or-later`.
