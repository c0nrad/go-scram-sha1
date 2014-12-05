# SCRAM-SHA1

Implements base case with [RFC](https://tools.ietf.org/html/rfc5802) test values.

Currently does all four messages and verifies client and server authenticity.

```
➜  scram git:(master) ✗ go run scram.go
C: n,,n=user,r=fyko+d2lbbFgONRv9qkxdawL
S: r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,s=QSXCR+Q6sek8bf92,i=4096
C: c=biws,r=fyko+d2lbbFgONRv9qkxdawL3rfcNHYJY1ZVvWVs7j,p=v0X8v3Bz2T0CJGbJQyF0X+HI4Ts=
S: v=rmF9pqV8S7suAoZWja4dJRkFsKQ=
Verified Client: true
Verified Server: true
```

c0nrad
