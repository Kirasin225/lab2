# ЛР2: Цифрові підписи (RSA PKCS#1 v1.5 + SHA‑1)

Самостійна реалізація RSA‑підпису з кодуванням EMSA‑PKCS1‑v1_5. Для хешування повідомлення використовується SHA‑1.

## Вимоги
- Go 1.22+

## Запуск
```bash
go run . keygen -bits 2048 -priv ./private.json -pub ./public.json
SIG=$(go run . sign -priv ./private.json -text "hello")
go run . verify -pub ./public.json -text "hello" -sig "$SIG"
```

## Тести
```bash
go test ./...
go vet ./...
```

