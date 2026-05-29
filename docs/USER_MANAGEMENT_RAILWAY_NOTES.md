# User Management — Railway Deployment Notes

## API Endpoints Used (no changes needed for Railway)
  GET    /api/v1/users/stats       → summary cards (total, admins, analysts, active)
  GET    /api/v1/users             → user list (returns { items: [...] } or array)
  PATCH  /api/v1/users/{id}        → update role ({ role: "admin"|"analyst" })
                                     or toggle active ({ is_active: true|false })
  DELETE /api/v1/users/{id}        → hard delete (permanently removes user row, returns 204)

## DELETE endpoint behaviour
  Returns 204 No Content on success.
  This is a HARD delete — the user row is permanently removed from the database.
  FK cleanup is handled in Python before the DELETE (see FK handling order below).
  Audit log entries for the deleted user are preserved (user_id set to NULL by PostgreSQL).
  Frontend removes the row with a fade-out animation on 204.

## Deactivate vs Delete distinction
  Deactivate: PATCH /users/{id} with { is_active: false }
    → user row status badge changes to Inactive in-place (no full reload)
    → user can be reactivated later via PATCH { is_active: true }

  Delete: DELETE /users/{id}
    → row fades out and is permanently removed from the DOM
    → user row is permanently deleted from the database (hard delete)
    → audit history is preserved (user_id nulled, not deleted)

## Guards that must work in production
  - Cannot delete your own account:
      Delete button is disabled (opacity 0.4, cursor not-allowed) for the
      logged-in user's own row. Clicking does nothing.
  - Cannot deactivate your own account:
      Deactivate button is disabled for your own row.
  - Cannot change your own role:
      Role dropdown is disabled for your own row.
  - Only Admin role can access User Management page at all:
      Backend returns 403 if non-admin calls any of these endpoints.
      Frontend hides the User Management nav item for non-admins.

## Inline confirmation pattern
  Deactivate, Reactivate, and Delete actions all show an inline
  confirmation row directly below the affected user row — NOT in a modal
  or at the bottom of the page. Only one confirmation row can be open at
  a time; opening a second closes the first automatically.

## No changes required for Railway
  All user management endpoints use relative API_BASE URL.
  As long as API_BASE points to the Railway URL, everything works.
  No environment variables specific to user management are needed.

## Delete User — Implementation Details

### What happens on DELETE /api/v1/users/{id}:
  FK handling is done in Python before the DELETE — no orphan data remains.

  Execution order inside a single transaction:

  1. invite_tokens WHERE invited_by_user_id = {id}
       → DELETE (column is NOT NULL / NO ACTION — cannot be nulled,
         must be explicitly deleted before the user row)

  2. export_jobs WHERE requested_by_user_id = {id}
       → DELETE (same reason — NOT NULL / NO ACTION constraint)

  3. audit_log entry written: action='user_deleted'
       under the acting admin (current_user.id), NOT the deleted user
       detail: { target_user_id, deleted_email, deleted_role }
       Written BEFORE db.delete(user) so it survives the commit.

  4. users row → permanently deleted (db.delete(user))

  PostgreSQL handles the remaining FKs automatically on user row delete:
    feedback.user_id              → SET NULL (feedback records preserved)
    audit_log.user_id             → SET NULL (historical entries preserved;
                                              user_id becomes NULL)
    password_reset_tokens.user_id → CASCADE DELETE (rows removed automatically)

  5. Returns 204 No Content

### No orphan data remains after delete.
### The audit log entry for the deletion is written under the admin who
### performed the delete, not the deleted user — so it is never nulled.

### audit_log display note:
  Existing audit log entries for the deleted user show user_id = NULL.
  The UI should display these as "Deleted User" rather than a blank name.

### Railway deployment: no changes needed.
  All FK handling is done in Python before the DELETE.
  No environment-specific configuration required.
