import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

public final class KernAuth {
  public String message = "";
  public String expiresAt = null;
  private final String api;
  private final String appId;
  private final String version;

  public KernAuth(String api, String appId) {
    this(api, appId, "");
  }

  public KernAuth(String api, String appId, String version) {
    this.api = api;
    this.appId = appId;
    this.version = version == null || version.isEmpty() ? "1.0.0" : version;
  }

  public static String checkBody(String appId, String licenseKey) {
    return checkBody(appId, licenseKey, "1.0.0");
  }

  public static String checkBody(String appId, String licenseKey, String version) {
    final String sent = version == null || version.isEmpty() ? "1.0.0" : version;
    return "{\"protocol_version\":1,\"public_app_id\":\"" + appId
        + "\",\"client_version\":\"" + sent + "\",\"license_key\":\"" + licenseKey + "\"}";
  }

  public static String apiMessage(String raw, String fallback) {
    if (raw == null) return fallback;
    final String marker = "\"message\":\"";
    final int start = raw.indexOf(marker);
    if (start < 0) return fallback;
    final int from = start + marker.length();
    final int end = raw.indexOf('"', from);
    if (end <= from) return fallback;
    return raw.substring(from, end);
  }

  public boolean check(String licenseKey) {
    try {
      HttpRequest request = HttpRequest.newBuilder(URI.create(api + "/v1/client/check"))
          .timeout(Duration.ofSeconds(10))
          .header("content-type", "application/json")
          .POST(HttpRequest.BodyPublishers.ofString(checkBody(appId, licenseKey, version)))
          .build();
      HttpResponse<String> response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
      String raw = response.body();
      boolean valid = raw.contains("\"valid\":true") || raw.contains("\"valid\": true");
      if (response.statusCode() != 200 || !valid) {
        message = apiMessage(raw, "check failed (" + response.statusCode() + ")");
        expiresAt = null;
        return false;
      }
      message = "License is active";
      expiresAt = readString(raw, "expires_at");
      return true;
    } catch (Exception error) {
      message = error.getMessage() == null ? "check failed" : error.getMessage();
      expiresAt = null;
      return false;
    }
  }

  private static String readString(String raw, String name) {
    final String marker = "\"" + name + "\":\"";
    final int start = raw.indexOf(marker);
    if (start < 0) return null;
    final int from = start + marker.length();
    final int end = raw.indexOf('"', from);
    return end <= from ? null : raw.substring(from, end);
  }
}
