# Parson

Upstream: https://github.com/kgabis/parson
Revision: ec53fb6528b45811df9db0db22cab96a94a96a11 (1.5.4)
License: MIT, preserved in LICENSE and source headers.

Original SHA256:

```text
a61370722e98609342278591c755a1632bf52281b0a054f2ef8a550ef456e799 parson.c
1909de7cdfa3b4383f2779ea6677b48a8a916ef975ca20c303ec5943459bb0f8 parson.h
ea4347d6cdbf46b37f436d02150fc7c4167280e8d0c3269b5d61ef1d0a002542 LICENSE
```

Local changes: nesting capped at 32; json_parse_string rejects trailing input;
parsed numbers retain their original token with lat_json_number_token for exact
uint64 validation. Only retirement metadata uses this parser. No serializer or
untrusted format-string interface is used by that validation path.
