using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Diagnostics;
using System.Text.Json;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using NetworkMonitor.Objects.ServiceMessage;
namespace NetworkMonitor.LLM.Services;
public class ProcessWrapper
{
     public DateTime LastActivity { get; set; } = DateTime.UtcNow;
    private bool _hasStarted = false;
    private Process _process;
    public ProcessWrapper()
    {
        _process = new Process();
    }
    public ProcessWrapper(Process? process = null)
    {
        if (process == null) _process = new Process();
        else _process = process;
    }
    public virtual IStreamWriter StandardInput => new StreamWriterWrapper(_process.StandardInput);
    public virtual IStreamReader StandardOutput => new StreamReaderWrapper(_process.StandardOutput);
    public virtual ProcessStartInfo StartInfo => _process.StartInfo;
    public virtual bool StandardOutputEndOfStream => _process.StandardOutput.EndOfStream;
    public virtual bool HasExited => _process.HasExited;
    public bool HasStarted => _hasStarted;
    public virtual void Kill() => _process.Kill();
    public virtual void Dispose() => _process.Dispose();
    public virtual int Id => _process.Id;
    public virtual void Start()
    {
        _process.Start();
        _hasStarted = true;
    }
    public virtual Task<string> StandardOutputReadLineAsync()
    {
        return _process.StandardOutput.ReadLineAsync()!;
    }
    public virtual Task StandardInputWriteLineAsync(string input)
    {
        return _process.StandardInput.WriteLineAsync(input);
    }
    public virtual Task StandardInputFlushAsync()
    {
        return _process.StandardInput.FlushAsync();
    }
    public virtual async Task<int> ReadAsync(byte[] buffer, int offset, int count)
    {
        return await _process.StandardOutput.BaseStream.ReadAsync(buffer, offset, count);
    }
     // New WaitForExit wrapper
    public virtual bool WaitForExit(int milliseconds)
    {
        return _process.WaitForExit(milliseconds);
    }

    public virtual void WaitForExit()
    {
        _process.WaitForExit();
    }
}
public interface IStreamReader
{
    Task<string> ReadLineAsync();
    Task<int> ReadAsync(byte[] buffer, int offset, int count);
    // Add other necessary methods from StreamReader
}
public interface IStreamWriter
{
    Task WriteLineAsync(string value);
    Task FlushAsync();
    // Add other necessary methods from StreamWriter
}
public class StreamReaderWrapper : IStreamReader
{
    private readonly StreamReader _innerStreamReader;
    public StreamReaderWrapper(StreamReader streamReader)
    {
        _innerStreamReader = streamReader;
    }
    public Task<string> ReadLineAsync()
    {
        return _innerStreamReader.ReadLineAsync()!;
    }
    public async Task<int> ReadAsync(byte[] buffer, int offset, int count)
    {
        return await _innerStreamReader.BaseStream.ReadAsync(buffer, offset, count);
    }
    // Implement other methods from IStreamReader if needed
}
public class StreamWriterWrapper : IStreamWriter
{
    private readonly StreamWriter _innerStreamWriter;
    public StreamWriterWrapper(StreamWriter streamWriter)
    {
        _innerStreamWriter = streamWriter;
    }
    public Task WriteLineAsync(string value)
    {
        return _innerStreamWriter.WriteLineAsync(value);
    }
    public Task FlushAsync()
    {
        return _innerStreamWriter.FlushAsync();
    }
    // Implement other methods from IStreamWriter if needed
}