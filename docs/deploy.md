# Deploying cordon

Back to the [README](../README.md).

No cache, no shared state: the vault is per request and ephemeral, policy is a JSON file, the audit log is a local file. One container, no Redis or database.

```bash
docker compose up -d --build      # from a clone: cordon on 127.0.0.1:8080, audit log on a volume
./deploy.sh                       # idempotent clone/pull/build/healthcheck to a remote box
```

Every tagged release publishes a multi-arch image (linux/amd64, linux/arm64) to GHCR with keyless Sigstore provenance and an SBOM. Verify it came from this repository's release workflow:

```bash
gh attestation verify oci://ghcr.io/askalf/cordon:v0.2.0 --repo askalf/cordon
```

Sharing one Claude or ChatGPT subscription through [dario](https://github.com/askalf/dario) without leaking PII: dario's [cordon integration guide](https://github.com/askalf/dario/blob/main/docs/integrations/cordon.md).
