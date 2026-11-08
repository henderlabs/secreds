# Contributing

Thanks for looking. This is a small security tool, so a few ground rules keep it trustworthy.

- **Never put a real credential in a commit, issue, test or screenshot.** Use obviously fake values. Treat every commit as public.
- **Security-relevant changes need a test.** Policy rules, Touch ID gates, masking and the GUI's access controls all have tests in `tests/`; a change that touches them should add or update one.
- **Keep it dependency-light.** The core uses the standard library and PyObjC. The only optional dependency is `cryptography` (for export and import).
- **Run the tests:** `python -m unittest discover -s tests -v`. They run on any OS.
- **Be honest in the docs.** If a change alters what seCreds does or does not protect against, update the README's security model and SECURITY.md in the same pull request.
- Open a pull request against `main`. Keep it focused, and describe what you tested.

To report a vulnerability, see [SECURITY.md](SECURITY.md).

---

<sub>**seCreds** v0.6.2 · by [henderlabs](https://github.com/henderlabs) · [Send feedback](https://github.com/henderlabs/secreds/issues/new/choose)</sub>
