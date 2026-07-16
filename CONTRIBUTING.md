# Contributing

`ai-agent-audit` is a small project run by one maintainer. PRs and issues are welcome; please read this first.

## Signed commits

All commits on `main` must be signed and verified. SSH commit signing setup is five minutes:

```bash
git config --global gpg.format ssh
git config --global user.signingkey ~/.ssh/<your-key>.pub
git config --global commit.gpgsign true
```

Register the same public key at https://github.com/settings/keys with type **Signing Key**. You can keep it as your Authentication Key as well — the same key works for both.

If your PR has unsigned commits, the maintainer may squash-merge it to land your work — GitHub signs the squashed commit on its end. For substantive multi-commit work, please sign your own commits so the authorship trail is preserved.

## Linear history

`main` is fast-forward-only. Merge commits are blocked. Rebase your branch onto `main` before opening a PR; the maintainer does the final fast-forward push.

## What's in scope

[`ROADMAP.md`](ROADMAP.md) lists v0.2 plans and what's explicitly out of scope. For substantive changes, please open an issue first to discuss direction before writing code.

Adapter requests should include the runtime name, your expected record volume, and the regulatory or operational obligation driving the ask.

## Contact

Maintainer: Nikolai Semernia. Open an issue at `github.com/Nik7A/ai-agent-audit`.
