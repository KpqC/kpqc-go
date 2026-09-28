# KpqC

> [!WARNING]
> The `github.com/KpqC/kpqc-go` module path is deprecated and no longer
> maintained. Use [`kpqc.dev`](https://pkg.go.dev/kpqc.dev) instead.

## Migration

Replace:

```go
import "github.com/KpqC/kpqc-go"
```

with:

```go
import "kpqc.dev"
```

Then update the dependency:

```sh
go get kpqc.dev@latest
go mod tidy
```
