# Migrations

Plain SQL files applied in lexicographic order by the `schema_owner` database role.

| File | Description |
|---|---|
| `001_initial.sql` | Core schema: sessions, events, detections, llm_usage, dashboard_users, roles (T5.1) |

Apply with:

```bash
psql "$DATABASE_URL" -f migrations/001_initial.sql
```

Never modify an applied migration. Add a new numbered file for schema changes.
