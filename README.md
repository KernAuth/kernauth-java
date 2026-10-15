# KernAuth Java example

Paste the public app ID from Developers into `src/main/java/Main.java`. JDK 21, with the pom.xml in this repository.

## Start

```java
KernAuth app = new KernAuth("https://api.kernauth.com", "__PUBLIC_APP_ID__");
```

Type the license at the prompt. `KERN_LICENSE_KEY` skips the prompt. The program checks that the key is valid and prints when it expires. It does not save a computer.

## Run

```
mvn -q compile exec:java
```

A modified program can still skip the check.

Documentation: https://kernauth.apidog.io
