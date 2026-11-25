# AI policy

Foster uses AI agents on purpose: reproducing a bug, drafting a minimal fix and writing regression
tests is exactly the slow work that left these packages orphaned. But AI-generated pull request
spam is also what ended Jazzband in 2026. So:

1. **Disclose.** Say in the PR description which tool helped and with what. Undisclosed AI-generated
   PRs are closed. Commits may carry a `Co-Authored-By:` line for the tool.
2. **A human owns every PR.** The person opening it has read every line and can answer questions
   about it. "The AI wrote it" is not an answer in review.
3. **Humans approve.** No patch is released without two human reviewers (see GOVERNANCE.md). Bots
   and agents can never approve.
4. **Tests are not optional.** An AI-drafted patch must come with tests that fail on the original
   release; the build script enforces this.
5. **No drive-by automation outside Foster.** Foster does not run agents that open issues or PRs in
   other people's repositories automatically. Every upstream contact is written or checked by a person
   and rate-limited.
6. **Low-effort submissions** (unrelated changes, hallucinated APIs, untested code) are closed
   without detailed review. Repeated ones lead to a block.
