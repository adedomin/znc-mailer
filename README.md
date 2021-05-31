# ZNC MAILER

Tool to send email on highlight

## Dependencies

cURL \w SMTP(S)

Boost

ZNC Development headers + znc-buildmod script.


## Build

```
mkdir build
# you could also use `getent passwd znc | cut -d: -f6`
cmake -DCMAKE_INSTALL_PREFIX="$(printf %s ~znc)"..
# Do not bother parallelizing; one compilation unit.
cmake --build .
cmake --install .
```

## Config

```
/msg *mailer get
```

# TODO: Fix this up.
