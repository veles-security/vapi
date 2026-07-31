# api

This module provides the shared API contracts, immutable models, stable errors, and conformance hooks for the Veles authentication ecosystem.

## Current scope

- common artifact abstractions
- principal and chain model types
- categorized error contract
- parsing/validation/issuance/exchange scheme interfaces
- basic exchange result and validation policy helpers

## Authentication chains

The [`aut`](./aut) package combines authentication mechanisms into policies
with `Chain`, `OR`, and `AND`. See the [authentication chain guide](./aut/README.md)
for construction examples and evaluation semantics.
