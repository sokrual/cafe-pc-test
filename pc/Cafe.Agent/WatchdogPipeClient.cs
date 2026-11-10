using System.IO.Pipes;
using System.Net;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace Cafe.Agent;

sealed class WatchdogPipeClient
{
    const string PipeName = "CafePc";
    sealed record Request(string Method, string Path, string? Body);
    sealed record Response(int Status, string Content);

    async Task<HttpResponseMessage> SendAsync(HttpMethod method, string path, object? body)
    {
        try
        {
            using var pipe = new NamedPipeClientStream(".", PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            await pipe.ConnectAsync(3000);
            using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, true);
            using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true };
            var request = new Request(method.Method, path, body is null ? null : JsonSerializer.Serialize(body));
            await writer.WriteLineAsync(JsonSerializer.Serialize(request));
            var line = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(12));
            if (line is null) throw new IOException("watchdog closed the pipe");
            var response = JsonSerializer.Deserialize<Response>(line) ?? throw new IOException("invalid watchdog response");
            return new HttpResponseMessage((HttpStatusCode)response.Status)
            {
                Content = new StringContent(response.Content ?? "", Encoding.UTF8, "application/json")
            };
        }
        catch (Exception e) when (e is IOException or TimeoutException)
        {
            throw new HttpRequestException("The watchdog is not reachable.", e);
        }
    }

    public Task<HttpResponseMessage> PostAsync(string path, object? body) => SendAsync(HttpMethod.Post, path, body);
    public Task<HttpResponseMessage> PostAsJsonAsync(string path, object body) => SendAsync(HttpMethod.Post, path, body);

    public async Task<T?> GetFromJsonAsync<T>(string path)
    {
        using var response = await SendAsync(HttpMethod.Get, path, null);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<T>();
    }
}
