# SKILL.md

Lessons learned from past mistakes in this repository.

## arpc response envelope

All `/api/` response examples in documentation must wrap the payload in the arpc envelope:

```json
{ "ok": true, "result": { ... } }
```

Void handlers (returning only `error`) produce:

```json
{ "ok": true }
```

Never document the inner payload alone — always show the full envelope.

## Database error handling

When using `pgctx.QueryRow(...).Scan(...)`, distinguish `sql.ErrNoRows` from real database errors. Never silently swallow all errors:

```go
err := pgctx.QueryRow(ctx, ...).Scan(...)
if errors.Is(err, sql.ErrNoRows) {
    // expected: no data yet
    return &result{}, nil
}
if err != nil {
    return nil, err  // real DB error — propagate
}
```

Always use `errors.Is` (not `==`) for error comparison to correctly handle wrapped errors.

## Bulk upserts with pgstmt

Use `pgstmt.Insert` for multi-row upserts instead of a per-row `Exec` loop. Use `OnConflictOnConstraint(...).DoUpdate(...)` with `ToRaw` for raw SQL expressions like `excluded.col` and `now()`. Use `pgstmt.Default` for columns covered by a schema default (no placeholder consumed):

```go
pgstmt.Insert(func(b pgstmt.InsertStatement) {
    b.Into("table")
    b.Columns("col1", "col2", "updated_at")
    for _, row := range chunk {
        b.Value(row.col1, row.col2, pgstmt.Default)
    }
    b.OnConflictOnConstraint("table_pkey").DoUpdate(func(b pgstmt.UpdateStatement) {
        b.Set("col2").ToRaw("excluded.col2")
        b.Set("updated_at").ToRaw("now()")
    })
}).ExecWith(ctx)
```

Chunk rows to avoid PostgreSQL's 65535-placeholder limit. Use `slices.Chunk` from stdlib:

```go
for chunk := range slices.Chunk(rows, 1000) {
    // pgstmt.Insert(...)
}
```
