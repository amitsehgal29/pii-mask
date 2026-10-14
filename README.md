# pii-mask

Mask PII columns in a CSV before sharing it outside a secure zone. It uses only the Python standard library.

## Usage

```bash
export PII_MASK_KEY='a-long-secret'
python3 pii_mask.py samples/customers.csv \
  --rule name=hash --rule email=email --rule phone=partial:4 --rule iban=drop -o masked.csv
```

```
customer_id,name,email,phone,city
C001,e2c863da00177e8b,43ef907c60@example.com,*********4567,Dubai
```

## Strategies

| Strategy | What it does |
|---|---|
| `hash` | Keyed HMAC-SHA256. The same input and key always give the same output, so masked files can still be joined. |
| `email` | Hashes the part before the @ and keeps the domain. |
| `partial:N` | Keeps the last N characters and stars the rest (default 4). |
| `redact[:TOKEN]` | Replaces the value with a fixed token. |
| `drop` | Removes the column. |

Empty values stay empty. A missing key, an unknown column or a bad rule exits with code 2. Without a secret key, hashes of short values like phone numbers can be reversed by guessing, so the key is required.

## Tests

```bash
python3 -m unittest
```
