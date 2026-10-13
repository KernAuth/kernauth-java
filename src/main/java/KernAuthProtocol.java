import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.TreeMap;

// Protocol example: mvn -f apps/web/src/examples/java/pom.xml exec:java
public final class KernAuthProtocol {
  private static final String API = "https://api.kernauth.com";
  private static final String APP_ID = "__PUBLIC_APP_ID__";
  private static final String KEY_ID = "__KEY_ID__";
  private static final String PUBLIC_KEY = "__PUBLIC_KEY__";
  private static final String[] FIELDS = {"protocol_version", "entitlement_id", "application_id", "license_id",
      "status", "features", "device_id", "issued_at", "expires_at", "server_time", "nonce", "key_id"};
  private static final ObjectMapper JSON = new ObjectMapper();
  private final String api;
  private final String appId;
  private final String keyId;
  private final String publicKey;
  public boolean success;
  public String message = "";

  public KernAuthProtocol(String api, String appId, String keyId, String publicKey) {
    this.api = api;
    this.appId = appId;
    this.keyId = keyId;
    this.publicKey = publicKey;
  }

  private static JsonNode sorted(JsonNode node) {
    if (node.isObject()) {
      ObjectNode out = JSON.createObjectNode();
      Map<String, JsonNode> entries = new TreeMap<>();
      node.fields().forEachRemaining(entry -> entries.put(entry.getKey(), entry.getValue()));
      entries.forEach((name, value) -> out.set(name, sorted(value)));
      return out;
    }
    if (node.isArray()) {
      ArrayNode out = JSON.createArrayNode();
      node.forEach(value -> out.add(sorted(value)));
      return out;
    }
    return node;
  }

  static byte[] canonical(JsonNode entitlement) throws Exception {
    StringBuilder result = new StringBuilder();
    for (String name : FIELDS) {
      JsonNode node = entitlement.required(name);
      String value = name.equals("features")
          ? JSON.writeValueAsString(sorted(node.isTextual() ? JSON.readTree(node.asText()) : node))
          : node.isTextual() ? node.asText() : node.toString();
      if (value.indexOf('\n') >= 0 || value.indexOf('\r') >= 0) throw new IllegalArgumentException("Invalid field");
      result.append(name).append('=').append(value).append('\n');
    }
    return result.toString().getBytes(StandardCharsets.UTF_8);
  }

  static boolean verify(JsonNode grant, String nonce, String app, String keyId, String publicKey, Instant now) {
    try {
      JsonNode ent = grant.required("entitlement");
      if (ent.required("protocol_version").asInt() != 1 ||
          !ent.required("nonce").asText().equals(nonce) ||
          !ent.required("application_id").asText().equals(app) ||
          !ent.required("key_id").asText().equals(keyId) ||
          !ent.required("status").asText().equals("active") ||
          !Instant.parse(ent.required("expires_at").asText()).isAfter(now)) return false;
      byte[] raw = Base64.getDecoder().decode(publicKey);
      if (raw.length != 32) return false;
      byte[] prefix = java.util.HexFormat.of().parseHex("302a300506032b6570032100");
      byte[] encoded = new byte[prefix.length + raw.length];
      System.arraycopy(prefix, 0, encoded, 0, prefix.length);
      System.arraycopy(raw, 0, encoded, prefix.length, raw.length);
      var key = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(encoded));
      Signature verifier = Signature.getInstance("Ed25519");
      verifier.initVerify(key); verifier.update(canonical(ent));
      return verifier.verify(Base64.getDecoder().decode(grant.required("signature").asText()));
    } catch (Exception ignored) { return false; }
  }

  public boolean activate(String license, String installation) {
    return call("activate", license, installation, "License is active");
  }

  public boolean validate(String license, String installation) {
    return call("validate", license, installation, "License is active");
  }

  public boolean deactivate(String license, String installation) {
    return call("deactivate", license, installation, "Device deactivated");
  }

  private boolean call(String mode, String license, String installation, String okMessage) {
    try {
      post(mode, license, installation);
      success = true;
      message = okMessage;
      return true;
    } catch (Exception error) {
      success = false;
      message = error.getMessage() == null ? "request failed" : error.getMessage();
      return false;
    }
  }

  private void post(String mode, String license, String installation) throws Exception {
    byte[] random = new byte[24]; new SecureRandom().nextBytes(random);
    String nonce = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    byte[] digest = MessageDigest.getInstance("SHA-256")
        .digest(("kernauth-device-v1:" + installation).getBytes(StandardCharsets.UTF_8));
    var body = Map.of("protocol_version", 1, "public_app_id", appId, "client_version", "1.0.0",
        "license_key", license, "fingerprint_version", 1, "device_fingerprint", java.util.HexFormat.of().formatHex(digest),
        "installation_id", installation, "nonce", nonce);
    HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
    HttpRequest outgoing = HttpRequest.newBuilder(URI.create(api + "/v1/client/" + mode))
        .timeout(Duration.ofSeconds(10)).header("Content-Type", "application/json")
        .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body))).build();
    HttpResponse<String> response = client.send(outgoing, HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != 200) throw new IllegalStateException(mode + " failed: " + response.statusCode());
    JsonNode grant = JSON.readTree(response.body());
    if (mode.equals("deactivate")) {
      if (!grant.required("deactivated").asBoolean()) throw new IllegalStateException("Deactivation not confirmed");
    } else if (!verify(grant, nonce, appId, keyId, publicKey, Instant.now()))
      throw new IllegalStateException("Invalid or expired signed entitlement");
  }

  private static void testVectors() throws Exception {
    JsonNode fixture = JSON.readTree(Files.readString(Path.of("vectors.json")));
    for (JsonNode vector : fixture.required("vectors")) {
      JsonNode ent = vector.required("fields");
      if (!new String(canonical(ent), StandardCharsets.UTF_8).equals(vector.required("canonical").asText()))
        throw new IllegalStateException("Canonical bytes differ");
      ObjectNode grant = JSON.createObjectNode();
      grant.set("entitlement", ent); grant.set("signature", vector.required("signature"));
      String nonce = ent.required("nonce").asText();
      String app = ent.required("application_id").asText();
      String key = ent.required("key_id").asText();
      String publicKey = vector.required("public_key").asText();
      Instant now = Instant.parse("2026-01-01T00:01:00Z");
      if (!verify(grant, nonce, app, key, publicKey, now) || verify(grant, "wrong", app, key, publicKey, now) ||
          verify(grant, nonce, "pub_other_app", key, publicKey, now) ||
          verify(grant, nonce, app, "wrong-key", publicKey, now) ||
          verify(grant, nonce, app, key, publicKey, now.plusSeconds(1200)))
        throw new IllegalStateException("Vector verification failed");
      ObjectNode forged = JSON.createObjectNode();
      forged.set("entitlement", ent); forged.put("signature", vector.required("signature").asText() + "AA");
      if (verify(forged, nonce, app, key, publicKey, now)) throw new IllegalStateException("Bad signature accepted");
    }
    System.out.println("Java vectors passed");
  }

  public static void main(String[] args) throws Exception {
    if (args.length > 0 && args[0].equals("--test-vectors")) { testVectors(); return; }
    String license = System.getenv("KERN_LICENSE_KEY");
    String installation = System.getenv("KERN_INSTALLATION_ID");
    if (license == null || installation == null) throw new IllegalArgumentException("Set KERN_LICENSE_KEY and KERN_INSTALLATION_ID");
    KernAuthProtocol app = new KernAuthProtocol(API, APP_ID, KEY_ID, PUBLIC_KEY);
    if (!app.activate(license, installation) || !app.validate(license, installation) || !app.deactivate(license, installation)) {
      throw new IllegalStateException(app.message);
    }
    System.out.println(app.message);
  }
}
