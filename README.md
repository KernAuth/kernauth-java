# KernAuth Java example

Protocol example for JDK 21. Paste the public app ID, key ID, and public key from the Developers page.

```
mvn -q compile exec:java -Dexec.args=--test-vectors
```

A patched program can still skip the check.

Documentation: https://kernauth.apidog.io
