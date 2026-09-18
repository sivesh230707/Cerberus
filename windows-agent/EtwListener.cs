using System;
using System.Collections.Generic;
using System.IO;

namespace Cerberus.WindowsAgent
{
    public class EtwTelemetryEvent
    {
        public string Timestamp { get; set; }
        public string EventType { get; set; }
        public string Category { get; set; }
        public string Severity { get; set; }
        public string Title { get; set; }
        public string Description { get; set; }
        public int ProcessId { get; set; }
        public Dictionary<string, string> Metadata { get; set; } = new Dictionary<string, string>();
    }

    /// <summary>
    /// Event Tracing for Windows (ETW) Listener for Cerberus.
    /// Captures process creation, file access, and network connect telemetry
    /// for sandboxed targets and evaluates against the 3 core MVP detection rules.
    /// </summary>
    public class EtwListener
    {
        // Core v1 Detection Rule Targets
        private static readonly HashSet<string> SensitivePaths = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Windows\System32\config\SAM",
            @"C:\Windows\System32\config\SYSTEM",
            @"C:\Windows\System32\config\SECURITY",
            @"AppData\Roaming\Microsoft\Vault",
            @"AppData\Local\Microsoft\Credentials"
        };

        public event Action<EtwTelemetryEvent> OnTelemetryEvent;
        public event Action<EtwTelemetryEvent> OnPolicyViolation;

        private readonly int _targetPid;
        private bool _isListening;

        public EtwListener(int targetPid)
        {
            _targetPid = targetPid;
        }

        public void Start()
        {
            _isListening = true;
            // In Phase 2: Attach to Microsoft-Windows-Kernel-Process,
            // Microsoft-Windows-Kernel-File, and Microsoft-Windows-Kernel-Network ETW sessions
        }

        public void Stop()
        {
            _isListening = false;
        }

        /// <summary>
        /// Evaluates file read events against Rule 2 (Sensitive path inspection).
        /// </summary>
        public void EvaluateFileAccess(int pid, string filePath, string desiredAccess)
        {
            if (!_isListening || pid != _targetPid) return;

            bool isSensitive = false;
            foreach (var sensitive in SensitivePaths)
            {
                if (filePath.IndexOf(sensitive, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    isSensitive = true;
                    break;
                }
            }

            if (isSensitive)
            {
                var evt = new EtwTelemetryEvent
                {
                    Timestamp = DateTime.Now.ToString("HH:mm:ss.fff"),
                    EventType = "FILE_ACCESS_VIOLATION",
                    Category = "filesystem",
                    Severity = "violation",
                    Title = "Rule Violation: Sensitive Path Read",
                    Description = $"Attempted read of protected credential path: {filePath}",
                    ProcessId = pid
                };
                evt.Metadata["Path"] = filePath;
                evt.Metadata["DesiredAccess"] = desiredAccess;
                OnPolicyViolation?.Invoke(evt);
            }
        }

        /// <summary>
        /// Evaluates network connection attempts against Rule 1 (Outbound network connection attempt).
        /// </summary>
        public void EvaluateNetworkConnect(int pid, string destIp, int destPort, string protocol)
        {
            if (!_isListening || pid != _targetPid) return;

            var evt = new EtwTelemetryEvent
            {
                Timestamp = DateTime.Now.ToString("HH:mm:ss.fff"),
                EventType = "NETWORK_VIOLATION",
                Category = "network",
                Severity = "violation",
                Title = "Rule Violation: Outbound Network Attempt",
                Description = $"Outbound {protocol} connection attempted to {destIp}:{destPort}",
                ProcessId = pid
            };
            evt.Metadata["DestinationIp"] = destIp;
            evt.Metadata["DestinationPort"] = destPort.ToString();
            evt.Metadata["Protocol"] = protocol;

            OnPolicyViolation?.Invoke(evt);
        }

        /// <summary>
        /// Evaluates child process spawns against Rule 3 (Unexpected child process spawn).
        /// </summary>
        public void EvaluateProcessCreate(int parentPid, int childPid, string imagePath, string commandLine)
        {
            if (!_isListening || parentPid != _targetPid) return;

            var evt = new EtwTelemetryEvent
            {
                Timestamp = DateTime.Now.ToString("HH:mm:ss.fff"),
                EventType = "CHILD_PROCESS_VIOLATION",
                Category = "process",
                Severity = "violation",
                Title = "Rule Violation: Unexpected Child Process",
                Description = $"Target spawned unauthorized child process '{Path.GetFileName(imagePath)}' (PID: {childPid})",
                ProcessId = parentPid
            };
            evt.Metadata["ChildPid"] = childPid.ToString();
            evt.Metadata["CommandLine"] = commandLine;

            OnPolicyViolation?.Invoke(evt);
        }
    }
}
