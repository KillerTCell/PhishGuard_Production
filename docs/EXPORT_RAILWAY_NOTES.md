# Export Feature — Railway Deployment Notes

## Critical: EXPORT_VOLUME_PATH

| Environment | Value | Persistence |
|---|---|---|
| Local Docker | `/mnt/exports` (named volume) | Persists across restarts |
| Railway | `/tmp/exports` (ephemeral) | Lost on container restart |

Railway does NOT have persistent volumes on the free tier.
Exports will be lost on container restart — acceptable for capstone demo purposes.

Set in Railway environment variables:
```
EXPORT_VOLUME_PATH=/tmp/exports
```

## Volume permissions — root cause of local failures

When Docker creates a named volume, the directory is owned by `root:root 0755`
by default. The Celery worker runs as the `phishguard` user (uid=100) and cannot
create subdirectories, causing:

```
PermissionError: [Errno 13] Permission denied: '/mnt/exports/<org_id>'
```

### Fix — baked into the Dockerfile

```dockerfile
# Pre-create the exports mount-point with correct ownership.
# Docker initialises a named volume from the image directory on first mount,
# so setting ownership here prevents the default root:root 0755 permissions.
RUN mkdir -p /mnt/exports && chown phishguard:phishguard /mnt/exports
```

This runs before `USER phishguard` in the final stage. On first volume mount Docker
copies the image directory (with phishguard ownership) into the named volume.

### If the volume already exists (pre-created as root)

Run once as a one-off fix:
```bash
docker compose exec -u root worker chown phishguard:phishguard /mnt/exports
```

## Both api AND worker must have the volume mounted

In `docker-compose.yml`, BOTH services need:
```yaml
volumes:
  - exports:/mnt/exports
```

On Railway, both the web service and the worker service need:
```
EXPORT_VOLUME_PATH=/tmp/exports
```

The `api` service needs the path to serve FileResponse downloads.
The `worker` service needs the path to write the generated files.

## File download requires the Authorization header

The `GET /settings/export/{job_id}` endpoint requires a valid JWT.
Direct `<a href>` links and `window.location.href` will NOT work — they cannot
send the Authorization header.

The frontend uses `apiFetch` (which adds the Bearer token) followed by
`response.blob()` + `URL.createObjectURL()` to trigger the browser download:

```javascript
async function downloadExport(jobId, format) {
    const resp = await apiFetch(`/settings/export/${jobId}`);
    if (!resp.ok) { showAppMessage("Export file could not be downloaded."); return; }
    const blob = await resp.blob();
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `phishguard-export.${format || 'csv'}`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
```

## Polling — how the frontend knows when the export is ready

After `POST /settings/export` returns 202, the frontend starts a `setInterval`
polling every 3 seconds:

```javascript
exportPollInterval = setInterval(renderDataExport, 3000);
```

Each poll calls `GET /settings/export/{job_id}`:
- If the response Content-Type is **not** `application/json` → status is `ready`
  → the binary blob is used to auto-trigger the download, interval is cleared.
- If the response is JSON and `status === 'failed'` → interval is cleared, error shown.
- Otherwise → history row is updated with current status, polling continues.

The SSE event `export_ready` also triggers `renderDataExport()` for real-time updates
(belt-and-suspenders with the polling).

## Export task queue

The worker must be subscribed to the `export` queue:
```
celery -A app.tasks.celery_app worker -Q analysis,digest,forwarding,export,maintenance,imap
```

Omitting `export` from `-Q` means export jobs will never be picked up.

## No other changes needed for Railway

The export query (emails + analysis_results + feedback LEFT JOINs) uses the
standard database connection — no extra configuration required.

Format support: `csv`, `json`, `jsonl`.
Date range: `7d`, `30d`, `all`.
Label filter: `all`, `phishing`, `safe`, `needs_investigation`.
