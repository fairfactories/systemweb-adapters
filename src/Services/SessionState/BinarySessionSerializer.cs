// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
//using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using static System.Net.Mime.MediaTypeNames;


namespace Microsoft.AspNetCore.SystemWebAdapters.SessionState.Serialization;

[System.Diagnostics.CodeAnalysis.SuppressMessage("Maintainability", "CA1510:Use ArgumentNullException throw helper", Justification = "Source shared with .NET Framework that does not have the method")]
internal partial class BinarySessionSerializer : ISessionSerializer
{
    private const byte Version = 1;

    private readonly SessionSerializerOptions _options;
    private readonly ISessionKeySerializer _serializer;
    private readonly ILogger<BinarySessionSerializer> _logger;

    public BinarySessionSerializer(ICompositeSessionKeySerializer serializer, IOptions<SessionSerializerOptions> options, ILogger<BinarySessionSerializer> logger)
    {
        _serializer = serializer;
        _options = options.Value;
        _logger = logger;
    }

    [LoggerMessage(EventId = 0, Level = LogLevel.Warning, Message = "Could not serialize unknown session key '{Key}'")]
    partial void LogSerialization(string key);

    [LoggerMessage(EventId = 1, Level = LogLevel.Warning, Message = "Could not deserialize unknown session key '{Key}'")]
    partial void LogDeserialization(string key);

    public void Write(ISessionState state, BinaryWriter writer)
    {
        try
        {
            string sessionId = state.SessionID;
            writer.Write(Version);
            writer.Write(sessionId);
            //CustomLogger.Log("BinarySessionSerializer~Write session id is: " + sessionId, LogLevelCustom.Critical);
            _logger.LogCritical("BinarySessionSerializer~Write session id is: " + sessionId);
            writer.Write(state.IsNewSession);
            writer.Write(state.IsAbandoned);
            writer.Write(state.IsReadOnly);
            writer.Write7BitEncodedInt(state.Timeout);
            writer.Write7BitEncodedInt(state.Count);

            List<string>? unknownKeys = null;

            // Use a copy of the Keys collection and associated values to avoid modification during iteration
            var keyValuePairs = state.Keys.ToDictionary(key => key, key => state[key]);

            foreach (var item in keyValuePairs)
            {
                writer.Write(item.Key);
                //CustomLogger.Log("serialize from core2~ session id is: " + sessionId + " Key is: " + item, LogLevelCustom.Critical);
                _logger.LogCritical("serialize from core~ session id is: " + sessionId + " Key is: " + item);
                if (_serializer.TrySerialize(item.Key, item.Value, out var result))
                {
                    //CustomLogger.Log("serialize from core~ session id is: " + sessionId + " Key is: " + item + " result is: " + result.Length, LogLevelCustom.Critical);
                    _logger.LogCritical("serialize from core~ session id is: " + sessionId + " Key is: " + item + " result is: " + result.Length);
                    writer.Write7BitEncodedInt(result.Length);
                    writer.Write(result);
                }
                else
                {
                    (unknownKeys ??= new()).Add(item.Key);
                    writer.Write7BitEncodedInt(0);
                }
            }

            if (unknownKeys is null)
            {
                writer.Write7BitEncodedInt(0);
            }
            else
            {
                writer.Write7BitEncodedInt(unknownKeys.Count);

                foreach (var key in unknownKeys)
                {
                    LogSerialization(key);
                    writer.Write(key);
                }
            }

            if (unknownKeys is not null && _options.ThrowOnUnknownSessionKey)
            {
                throw new UnknownSessionKeyException(unknownKeys);
            }
        }
        catch (Exception ex)
        {
            CustomLogger.Log("BinarySessionSerializer write Exception: " + state.SessionID + " exception: " + ex.Message, LogLevelCustom.Critical);
            _logger.LogCritical("BinarySessionSerializer write Exception: " + state.SessionID + " exception: " + ex.Message);
        }
    }


    public ISessionState Read(BinaryReader reader)
    {
        try
        {
            if (reader is null)
            {
                throw new ArgumentNullException(nameof(reader));
            }

            if (reader.ReadByte() != Version)
            {
                throw new InvalidOperationException("Serialized session state has different version than expected");
            }
            //CustomLogger.Log("BinarySessionSerializer~read method start", LogLevelCustom.Critical);
            _logger.LogCritical("BinarySessionSerializer~read method start");

            var state = new BinaryReaderSerializedSessionState(reader, _serializer, _logger);

            if (state.UnknownKeys is { Count: > 0 } unknownKeys)
            {
                foreach (var unknown in unknownKeys)
                {
                    LogDeserialization(unknown);
                }

                if (_options.ThrowOnUnknownSessionKey)
                {
                    throw new UnknownSessionKeyException(unknownKeys);
                }
            }

            return state;
        }
        catch (Exception ex)
        {
            CustomLogger.Log("BinarySessionSerializer Read main method Exception: ", LogLevelCustom.Critical);
            _logger.LogCritical("BinarySessionSerializer Read main method Exception: " + ex.Message.ToString());
            return null;
        }
    }


    public Task<ISessionState?> DeserializeAsync(Stream stream, CancellationToken token)
    {
        using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);

        return Task.FromResult<ISessionState?>(Read(reader));
    }

    public Task SerializeAsync(ISessionState state, Stream stream, CancellationToken token)
    {
        using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);

        Write(state, writer);

        return Task.CompletedTask;
    }

    private class BinaryReaderSerializedSessionState : ISessionState
    {
        private readonly ILogger<BinarySessionSerializer> _logger;
        public BinaryReaderSerializedSessionState(BinaryReader reader, ISessionKeySerializer serializer, ILogger<BinarySessionSerializer> logger)
        {
            try
            {
                _logger = logger;
                SessionID = reader.ReadString();
                IsNewSession = reader.ReadBoolean();
                IsAbandoned = reader.ReadBoolean();
                IsReadOnly = reader.ReadBoolean();
                Timeout = reader.Read7BitEncodedInt();

                var count = reader.Read7BitEncodedInt();

                for (var index = count; index > 0; index--)
                {

                    var key = reader.ReadString();
                    var length = reader.Read7BitEncodedInt();
                    var bytes = reader.ReadBytes(length);
                    try
                    {
                        _logger.Log(LogLevel.Critical, "BinaryReaderSerializedSessionState read method session id is: " + SessionID + " Key is: " + key);
                        if (serializer.TryDeserialize(key, bytes, out var result))
                        {
                            if (result is not null)
                            {
                                this[key] = result;
                            }
                        }
                        else
                        {
                            (UnknownKeys ??= new()).Add(key);
                        }
                    }
                    catch (Exception ex)
                    {
                        CustomLogger.Log("BinaryReaderSerializedSessionState loop error session id is: " + SessionID + " Key is " + Convert.ToString(key) + " exception is:" + ex.Message.ToString(), LogLevelCustom.Critical);
                        _logger.LogCritical("BinaryReaderSerializedSessionState loop error session id is: " + SessionID + " Key is " + Convert.ToString(key) + " exception is:" + ex.Message.ToString());
                    }


                }

                var unknown = reader.Read7BitEncodedInt();

                if (unknown > 0)
                {
                    for (var index = unknown; index > 0; index--)
                    {
                        (UnknownKeys ??= new()).Add(reader.ReadString());
                    }
                }
            }
            catch (Exception ex)
            {
                CustomLogger.Log("BinaryReaderSerializedSessionState main class error session id is: " + SessionID + " exception is:" + ex.Message.ToString(), LogLevelCustom.Critical);
                _logger.LogCritical("BinaryReaderSerializedSessionState main class error session id is: " + SessionID + " exception is:" + ex.Message.ToString());
            }


        }

        private Dictionary<string, object?>? _items;

        public object? this[string key]
        {
            get => _items?.TryGetValue(key, out var result) is true ? result : null;
            set => (_items ??= new())[key] = value;
        }

        internal List<string>? UnknownKeys { get; private set; }

        public string SessionID { get; set; } = null!;

        public bool IsReadOnly { get; set; }

        public int Timeout { get; set; }

        public bool IsNewSession { get; set; }

        public int Count => _items?.Count ?? 0;

        public bool IsAbandoned { get; set; }

        bool ISessionState.IsSynchronized => false;

        object ISessionState.SyncRoot => this;

        IEnumerable<string> ISessionState.Keys => _items?.Keys ?? Enumerable.Empty<string>();

        void ISessionState.Clear() => _items?.Clear();

        void ISessionState.Remove(string key) => _items?.Remove(key);

        Task ISessionState.CommitAsync(CancellationToken token) => Task.CompletedTask;

        void IDisposable.Dispose()
        {
        }
    }
}

public static class CustomLogger
{
    private static readonly object LockObject = new object();
    private static readonly string LogFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs", "log.txt");

    public static void Log(string message, LogLevelCustom level)
    {
        string formattedMessage = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}{Environment.NewLine}";

        lock (LockObject)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(LogFilePath));
            File.AppendAllText(LogFilePath, formattedMessage);
        }
    }
}

public enum LogLevelCustom
{
    Debug,
    Information,
    Warning,
    Error,
    Critical
}

