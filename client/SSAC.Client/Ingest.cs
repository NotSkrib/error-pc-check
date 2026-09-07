using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SSAC.Client;

/// <summary>
/// Talks to the SSAC ingest Edge Function. Every request body is signed with
/// HMAC-SHA256 using the raw session key as the shared secret
/// (docs/phase-0-design.md §2.2 A3). Optional SPKI pinning guards the TLS channel.
/// </summary>
public sealed class IngestClient : IDisposable
{
    private readonly HttpClient _http;
    private readonly string _key;
    private readonly string _endpoint;

    public IngestClient(string endpoint, string key, string? pinnedSpkiSha256Base64 = null)
    {
        _endpoint = endpoint.TrimEnd('/');
        _key = key;

        var handler = new HttpClientHandler();
        if (!string.IsNullOrWhiteSpace(pinnedSpkiSha256Base64))
        {
            handler.ServerCertificateCustomValidationCallback = (_, cert, _, errors) =>
            {
                if (errors != System.Net.Security.SslPolicyErrors.None || cert is null) return false;
                var spki = cert.PublicKey.EncodedKeyValue.RawData;
                var hash = Convert.ToBase64String(SHA256.HashData(spki));
                return CryptographicOperations.FixedTimeEquals(
                    Encoding.ASCII.GetBytes(hash),
                    Encoding.ASCII.GetBytes(pinnedSpkiSha256Base64));
            };
        }

        _http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };
        _http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", _key);
        _http.DefaultRequestHeaders.UserAgent.ParseAdd($"ssac-client/{AppInfo.Version}");
    }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private async Task<JsonDocument> PostAsync(string action, object payload, CancellationToken ct)
    {
        var body = JsonSerializer.Serialize(payload, JsonOpts);
        using var msg = new HttpRequestMessage(HttpMethod.Post, $"{_endpoint}/ingest")
        {
            Content = new StringContent(body, Encoding.UTF8, "application/json"),
        };
        var sig = Convert.ToHexString(
            new HMACSHA256(Encoding.UTF8.GetBytes(_key)).ComputeHash(Encoding.UTF8.GetBytes(body)))
            .ToLowerInvariant();
        msg.Headers.Add("x-ssac-sig", sig);

        HttpResponseMessage resp;
        string text;
        try
        {
            resp = await _http.SendAsync(msg, ct);
            text = await resp.Content.ReadAsStringAsync(ct);
        }
        catch (Exception ex) when (ex is not IngestException)
        {
            throw new IngestException(
                "Couldn't reach the panel. Check your internet connection and try again.",
                $"{action}: {ex.GetType().Name}: {ex.Message}");
        }

        using (resp)
        {
            if (!resp.IsSuccessStatusCode)
                throw new IngestException(
                    Friendly((int)resp.StatusCode, text),
                    $"{action} {(int)resp.StatusCode}: {text}");
            return JsonDocument.Parse(text);
        }
    }

    /// <summary>Turns the ingest error body into something a player can act on.</summary>
    private static string Friendly(int status, string body)
    {
        var err = "";
        try
        {
            using var d = JsonDocument.Parse(body);
            if (d.RootElement.TryGetProperty("error", out var e)) err = e.GetString() ?? "";
        }
        catch { /* not JSON */ }

        return err switch
        {
            "key expired" or "key revoked" =>
                "This screenshare link has expired. Ask the staff member for a new one.",
            "key already used" =>
                "This screenshare link has already been used. Ask the staff member for a new one.",
            "unknown key" or "missing key" or "bad signature" =>
                "This screenshare link isn't valid. Ask the staff member for a new one.",
            _ when status == 409 =>
                "This screenshare has already been run. Ask the staff member for a new link.",
            _ when status >= 500 =>
                "The panel had a problem. Wait a minute and try again.",
            _ =>
                "Couldn't start the screenshare. Ask the staff member for a new link.",
        };
    }

    public async Task<SessionDescription> DescribeAsync(CancellationToken ct)
    {
        using var doc = await PostAsync("describe", new { action = "describe" }, ct);
        var r = doc.RootElement;
        return new SessionDescription(
            r.GetProperty("server_name").GetString() ?? "Unknown server",
            r.GetProperty("case_label").GetString() ?? "",
            r.TryGetProperty("suspect_label", out var sl) ? sl.GetString() : null,
            r.GetProperty("expires_at").GetDateTimeOffset(),
            r.TryGetProperty("already_used", out var au) && au.GetBoolean());
    }

    public async Task<string> StartAsync(ConsentPayload consent, EnvironmentPayload env, CancellationToken ct)
    {
        using var doc = await PostAsync("start", new
        {
            action = "start",
            consent,
            environment = env,
            client_version = AppInfo.Version,
            signature_db_version = AppInfo.SignatureDbVersion,
        }, ct);
        return doc.RootElement.GetProperty("report_id").GetString()!;
    }

    public Task EventAsync(string kind, string? module, string message, int? pct, CancellationToken ct)
        => Swallow(PostAsync("event", new { action = "event", kind, module, message, pct }, ct));

    public Task FindingAsync(FindingPayload f, CancellationToken ct)
        => PostAsync("finding", new
        {
            action = "finding",
            module = f.Module,
            severity = f.Severity,
            title = f.Title,
            description = f.Description,
            evidence = f.Evidence,
            occurred_at = f.OccurredAt,
            sort_key = f.SortKey,
        }, ct).ContinueWith(t => t.Result.Dispose(), ct);

    public Task CompleteAsync(string verdict, Dictionary<string, int> counts, bool aborted, CancellationToken ct)
        => Swallow(PostAsync("complete", new
        {
            action = "complete",
            verdict_severity = verdict,
            findings_count = counts,
            status = aborted ? "aborted" : "complete",
        }, ct));

    private static async Task Swallow(Task<JsonDocument> t)
    {
        try { (await t).Dispose(); } catch (IngestException) { /* progress events are best-effort */ }
    }

    public void Dispose() => _http.Dispose();
}

public sealed class IngestException(string message, string? detail = null) : Exception(message)
{
    /// <summary>Technical detail for the crash log, kept out of the user dialog.</summary>
    public string? Detail { get; } = detail;
}

public readonly record struct SessionDescription(
    string ServerName, string CaseLabel, string? SuspectLabel, DateTimeOffset ExpiresAt, bool AlreadyUsed);

public sealed record ConsentPayload
{
    [JsonPropertyName("accepted")] public bool Accepted { get; init; }
    [JsonPropertyName("at")] public DateTimeOffset At { get; init; }
    [JsonPropertyName("browser_history_optin")] public bool BrowserHistoryOptIn { get; init; }
    [JsonPropertyName("server_name_shown")] public string ServerNameShown { get; init; } = "";
    [JsonPropertyName("case_label")] public string CaseLabel { get; init; } = "";
}

public sealed record EnvironmentPayload
{
    [JsonPropertyName("os_build")] public string OsBuild { get; init; } = "";
    [JsonPropertyName("uptime_seconds")] public long UptimeSeconds { get; init; }
    [JsonPropertyName("is_vm")] public bool IsVm { get; init; }
    [JsonPropertyName("debugger_present")] public bool DebuggerPresent { get; init; }
    [JsonPropertyName("client_hash_ok")] public bool ClientHashOk { get; init; }
    [JsonPropertyName("client_sha256")] public string ClientSha256 { get; init; } = "";
    [JsonPropertyName("parent_process")] public string ParentProcess { get; init; } = "";
    [JsonPropertyName("elevated")] public bool Elevated { get; init; }
}

public sealed record FindingPayload(
    string Module, string Severity, string Title, string Description,
    object Evidence, DateTimeOffset? OccurredAt, int SortKey);
