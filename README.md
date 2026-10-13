# KernAuth Java example

Protocol example for JDK 21. This is not the official SDK. The official client is the C++ SDK. This file calls validate and checks the Ed25519 signature.

## Add it

Paste the public app ID, key ID, and public key from Developers over the placeholders in `KernAuthProtocol.java`.

```
mvn -q compile exec:java -Dexec.args=--test-vectors
```

Run with `KERN_LICENSE_KEY` and `KERN_INSTALLATION_ID` set. Persist one installation ID per device.

## Instance

```java
KernAuthProtocol app = new KernAuthProtocol(
    "https://api.kernauth.com",
    "__PUBLIC_APP_ID__",
    "__KEY_ID__",
    "__PUBLIC_KEY__");
```

## Validate

```java
if (!app.validate(license, installation)) {
    throw new IllegalStateException(app.message);
}
```

A patched program can still skip the check. These examples do not add anti-debug or anti-VM code.

Documentation: https://kernauth.apidog.io
