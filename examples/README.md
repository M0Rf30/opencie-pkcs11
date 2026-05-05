# Examples — opencie-pkcs11

Standalone C programs demonstrating each part of the public API.

## Build

```bash
gcc -o enrol        enrol.c        -lopencie-pkcs11
gcc -o sign_pdf     sign_pdf.c     -lopencie-pkcs11
gcc -o verify_doc   verify_doc.c   -lopencie-pkcs11
gcc -o get_cert     get_cert.c     -lopencie-pkcs11
gcc -o reader_watch reader_watch.c -lopencie-pkcs11
```

Or with an explicit library path:

```bash
gcc -o enrol enrol.c -I../include -L../builddir -lopencie-pkcs11 -Wl,-rpath,../builddir
```

## Examples

| File | Demonstrates |
|------|-------------|
| `enrol.c` | Card enrolment (`cie_enable`) |
| `sign_pdf.c` | PDF signing (`cie_sign`) |
| `verify_doc.c` | Document verification (`cie_verify`, `cie_get_verify_info`) |
| `get_cert.c` | Certificate retrieval (`cie_get_certificate`) |
| `reader_watch.c` | Reader hot-plug detection (`cie_reader_watch`) |
