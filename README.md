# KernAuth Java example

Paste the public app ID, key ID, and public key from Developers into `KernAuthProtocol.java`. JDK 21, with the adjacent pom.xml and Jackson.

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
System.out.println("Status: " + app.status);
System.out.println("Features: " + app.features);
System.out.println("License: " + app.licenseId);
System.out.println("Check expires: " + app.expiresAt);
```

A good check prints the status, the feature flags stored on the license, the license id, and when this check expires. Type the license key at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program saves an installation id in `kernauth-install` and reuses it. `KERN_INSTALLATION_ID` overrides that file.

## Run

```
mvn -q compile exec:java -Dexec.args=--test-vectors
mvn -q compile exec:java
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
