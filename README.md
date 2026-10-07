# Atrekos open exchange formats

JSON Schemas (draft 2020-12) for the files Atrekos writes and reads, generated from the product's own
type definitions. Each schema's `$id` is its address under https://data.atrekos.com/schemas.

- `schemas/index.json` lists every schema, the Atrekos versions it covers and its address.
- `schemas/<name>/<version>.json` is one schema.
- `examples/` is reserved for worked examples.

The schemas describe shape only. They carry no framework text and do not change the licence a framework
file or an export carries. Atrekos is not affiliated with the bodies whose frameworks it can hold.

This repository is updated by hand from the product repository (`docs/runbooks/schemas.md`); do not edit
files here.
