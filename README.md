# ZNC MAILER

Tool to send email on highlight

## Dependencies

cURL  - (SMTP Feature)
Boost
ZNC


## Build

```
mkdir build
cmake ..
# Don't bother parallelizing
cmake --build .
cp lib/libmailer.so ~znc/.znc/modules/mailer.so
```

## Config

```
/msg *mailer get
```

# TODO: Fix this up.
