# Vendored spec

`cybersource-rest-spec.json` is Cybersource's merged REST spec (Swagger 2.0), copied from
the official Python SDK so the spec and the auth vectors come from the same release.

| | |
|---|---|
| Repository | `CyberSource/cybersource-rest-client-python` |
| Tag | `0.0.81` |
| Path | `generator/cybersource-rest-spec.json` |
| URL | <https://raw.githubusercontent.com/CyberSource/cybersource-rest-client-python/0.0.81/generator/cybersource-rest-spec.json> |
| Bytes | 21586919 |
| SHA-256 | `264f9901164135fa0bc3adfba69d20687f375ea9a630b3b99cf9fdd5d5038363` |

Update with `cargo xtask update-spec <tag>`, then `cargo xtask codegen`, and review the diff.
The spec's own `info.version` is always `0.0.1`, so the SDK tag is the version.
