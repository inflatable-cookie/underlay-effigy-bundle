# Immutable nerdctl formatter controls

Apache-2.0 source and maintained tests copied from nerdctl commit
`04f63fe15f3f8d77fe41e56ab7ff1d1f3e312860` (reported v2.3.1):

- [formatter source](https://github.com/containerd/nerdctl/blob/04f63fe15f3f8d77fe41e56ab7ff1d1f3e312860/pkg/formatter/formatter.go)
- [maintained tests](https://github.com/containerd/nerdctl/blob/04f63fe15f3f8d77fe41e56ab7ff1d1f3e312860/pkg/formatter/formatter_test.go)

The control model checks these maintained goldens before supplying rows to the
actual pinned native parser/serializer and helper in private backend doubles.
It does not execute Go, attest guest binary bytes or grant runtime credit.
