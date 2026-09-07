namespace SSAC.Client;

/// <summary>
/// Best-effort crash reporting to the panel's `client-error` Edge Function — a
/// small self-hosted stand-in for Sentry. Never throws, never blocks for long,
/// and caps how many reports one run may send. Not HMAC-signed on purpose: the
/// client may be reporting *because* signing or JSON serialisation is what broke.
/// </summary>
internal static class Telemetry
{
    private static string _endpoint = AppInfo.DefaultEndpoint;
    private static string? _key;
    private static int _sent;

    /// <summary>Called once the endpoint / key are known (after Options.Parse).</summary>
    public static void Configure(string endpoint, string? key)
    {
        if (!string.IsNullOrWhiteSpace(endpoint)) _endpoint = endpoint.TrimEnd('/');
        _key = key;
    }

    /// <summary>Report a crash. Synchronous with a hard timeout — the app is
    /// already failing, so a short blocking send is more reliable than a
    /// fire-and-forget task the process may not live long enough to run.</summary>
    public static void Report(string phase, Exception? ex)
    {
        if (Interlocked.Increment(ref _sent) > 6) return;
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var payload = new
            {
                key = _key,
                phase,
                client_version = AppInfo.Version,
                os_build = Environment.OSVersion.VersionString,
                exception_type = ex?.GetType().FullName,
                message = ex is IngestException { Detail: { } d } ? $"{ex.Message} — {d}" : ex?.Message,
                stack = ex?.ToString(),
            };
            var body = System.Text.Json.JsonSerializer.Serialize(payload);
            using var msg = new HttpRequestMessage(HttpMethod.Post, $"{_endpoint}/client-error")
            {
                Content = new StringContent(body, System.Text.Encoding.UTF8, "application/json"),
            };
            using var _ = http.Send(msg);
        }
        catch { /* diagnostics must never crash the crash handler */ }
    }
}
