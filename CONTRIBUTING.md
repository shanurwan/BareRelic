# Contributing

## Ground rules

1. **Never write to a source.** No code path may open a source for writing.
   New sources implement `source.Source`, which has no write method.
2. **Standard library only.** Adding a dependency needs a strong reason
   recorded in the pull request.
3. **Treat every byte from a source as hostile.** Bound allocations by bytes
   that physically exist, guard every loop that follows on-disk pointers,
   and add a fuzz target for every new parser.
4. **Plan, then read.** File-system and carving code produce an
   `extent.List` plus confidence and notes; only the CLI reads bytes into a
   case. Do not bypass `evidence.Case`.
5. **Be honest about uncertainty.** If recovery assumes something, lower the
   confidence and say what was assumed in a note.
6. **Tests come from specifications, not from the parser.** Build fixtures
   with the independent builders in `internal/testutil` (or extend them) so
   a parser bug cannot hide in a shared assumption.

## Workflow

```sh
make check      # gofmt + vet + tests (must pass)
make race       # on Linux/macOS with cgo
make lint vuln  # staticcheck, govulncheck
make fuzz       # before touching any parser
```

- Keep commits focused; describe *why* in the message.
- Update `CHANGELOG.md` and the relevant `docs/` page for behaviour changes.
- Never commit disk images, rescue maps or case directories (`.gitignore`
  blocks the common extensions); use generated fixtures instead.

## Adding a carving format

1. Add a `Signature` in `internal/carve/carve.go` with a sane `MaxSize`.
2. Write a validator that walks the format's structure and returns the exact
   length, or `invalid()`; never trust a declared size beyond `s.limit`.
3. Add a real sample (preferably produced by the standard library) to the
   corpus in `carve_test.go`, a damaged-sample rejection case, and a fuzz seed.
