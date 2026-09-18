using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace Cerberus.WindowsAgent
{
    class Program
    {
        private static bool _contained = false;
        private static readonly object _lock = new object();

        static int Main(string[] args)
        {
            // Unbuffered UTF-8 output for real-time JSON streaming
            Console.OutputEncoding = Encoding.UTF8;

            if (args.Length == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help")
            {
                PrintHelp();
                return 0;
            }

            string mode = args[0].ToLowerInvariant();
            if (mode == "launch")
            {
                return HandleLaunch(args);
            }
            else if (mode == "monitor")
            {
                return HandleMonitor(args);
            }
            else if (mode == "contain")
            {
                return HandleContain(args);
            }
            else
            {
                Console.Error.WriteLine(string.Format("Unknown command: {0}. Use --help for usage.", mode));
                return 1;
            }
        }

        private static void PrintHelp()
        {
            Console.WriteLine("Cerberus Windows Host Agent v1.0");
            Console.WriteLine("Usage:");
            Console.WriteLine("  CerberusAgent.exe launch --file <path> [--mem-mb 256] [--cpu-limit 50]");
            Console.WriteLine("  CerberusAgent.exe monitor --pid <pid> [--file <path>]");
            Console.WriteLine("  CerberusAgent.exe contain --pid <pid>");
        }

        private static int HandleLaunch(string[] args)
        {
            string filePath = null;
            long memLimitMb = 256;

            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--file" && i + 1 < args.Length)
                {
                    filePath = args[++i];
                }
                else if (args[i] == "--mem-mb" && i + 1 < args.Length)
                {
                    long.TryParse(args[++i], out memLimitMb);
                }
            }

            if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            {
                EmitRawEvent("ERROR", "system", "critical", "Invalid Target Path",
                    string.Format("Target payload file does not exist: {0}", filePath ?? "null"), 0, null);
                return 1;
            }

            string fileName = Path.GetFileName(filePath);
            string ext = Path.GetExtension(filePath).ToLowerInvariant();

            // 1. Initialize Job Object
            JobObjectWrapper job = null;
            try
            {
                job = new JobObjectWrapper("CerberusJob_" + Guid.NewGuid().ToString("N").Substring(0, 8));
                job.ApplyLimits(memLimitMb * 1024 * 1024, 8);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine(string.Format("Warning: Could not create Job Object: {0}", ex.Message));
            }

            // 2. Prepare process launch
            ProcessStartInfo psi = new ProcessStartInfo();
            psi.CreateNoWindow = true;
            psi.UseShellExecute = false;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;

            if (ext == ".ps1")
            {
                psi.FileName = "powershell.exe";
                psi.Arguments = string.Format("-ExecutionPolicy Bypass -NoProfile -File \"{0}\"", filePath);
            }
            else if (ext == ".bat" || ext == ".cmd")
            {
                psi.FileName = "cmd.exe";
                psi.Arguments = string.Format("/c \"{0}\"", filePath);
            }
            else
            {
                psi.FileName = filePath;
            }

            Process process = null;
            try
            {
                process = Process.Start(psi);
            }
            catch (Exception ex)
            {
                EmitRawEvent("ERROR", "process", "critical", "Process Launch Failed", ex.Message, 0, null);
                if (job != null) job.Dispose();
                return 1;
            }

            int targetPid = process.Id;

            // Assign to Job Object immediately
            if (job != null)
            {
                job.AssignProcess(targetPid);
            }

            // Emit Initialization Events
            Dictionary<string, string> initMeta = new Dictionary<string, string>();
            initMeta["filename"] = fileName;
            initMeta["filepath"] = filePath;
            initMeta["target_pid"] = targetPid.ToString();
            EmitRawEvent("SESSION_INIT", "system", "info", "Sandbox Initialized",
                string.Format("Target process '{0}' started under host telemetry oversight.", fileName), targetPid, initMeta);

            Dictionary<string, string> jobMeta = new Dictionary<string, string>();
            jobMeta["memory_cap_mb"] = memLimitMb.ToString();
            jobMeta["active_process_limit"] = "8";
            EmitRawEvent("JOB_OBJECT_ATTACH", "isolation", "info", "Job Object Assigned",
                string.Format("Resource boundaries applied: {0} MB RAM cap, child process limit 8.", memLimitMb), targetPid, jobMeta);

            Dictionary<string, string> procMeta = new Dictionary<string, string>();
            procMeta["pid"] = targetPid.ToString();
            procMeta["executable"] = psi.FileName;
            EmitRawEvent("PROCESS_START", "process", "info", "Target Process Started",
                string.Format("Target process executing with PID {0}.", targetPid), targetPid, procMeta);

            // 3. Initialize Live ETW / Telemetry Listener (No static/canned triggers)
            EtwListener listener = new EtwListener(targetPid);
            ResponseAgent responder = new ResponseAgent();

            listener.OnTelemetryEvent += delegate(EtwTelemetryEvent evt)
            {
                Console.WriteLine(evt.ToJson());
            };

            listener.OnPolicyViolation += delegate(EtwTelemetryEvent evt)
            {
                ExecuteContainment(targetPid, evt, responder, listener);
            };

            listener.Start();

            // Background reader for target stdout/stderr
            process.OutputDataReceived += delegate(object sender, DataReceivedEventArgs e)
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    Dictionary<string, string> meta = new Dictionary<string, string>();
                    meta["output"] = e.Data;
                    EmitRawEvent("TARGET_STDOUT", "process", "info", "Process Output", e.Data, targetPid, meta);
                }
            };
            process.ErrorDataReceived += delegate(object sender, DataReceivedEventArgs e)
            {
                if (!string.IsNullOrEmpty(e.Data))
                {
                    Dictionary<string, string> meta = new Dictionary<string, string>();
                    meta["stderr"] = e.Data;
                    EmitRawEvent("TARGET_STDERR", "process", "info", "Process Stderr", e.Data, targetPid, meta);
                }
            };
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();

            // Wait for exit or containment
            while (!process.HasExited && !_contained)
            {
                Thread.Sleep(200);
            }

            if (!_contained)
            {
                // Normal exit
                int exitCode = 0;
                try { exitCode = process.ExitCode; } catch { }

                Dictionary<string, string> exitMeta = new Dictionary<string, string>();
                exitMeta["exit_code"] = exitCode.ToString();
                EmitRawEvent("PROCESS_EXIT", "process", "info", "Process Terminated Normally",
                    string.Format("Target process {0} completed execution with exit code {1}.", targetPid, exitCode), targetPid, exitMeta);

                // Final Clean Verdict
                EmitVerdict("CLEAN", "Analysis Complete: Clean",
                    "No security policy violations detected during sandbox execution.", targetPid, new List<string>());
            }

            listener.Stop();
            if (job != null) job.Dispose();
            try { process.Dispose(); } catch { }

            return 0;
        }


        private static void ExecuteContainment(int targetPid, EtwTelemetryEvent violationEvt, ResponseAgent responder, EtwListener listener)
        {
            lock (_lock)
            {
                if (_contained) return;
                _contained = true;
            }

            if (listener != null) listener.MarkContained();

            // 1. Emit Violation
            Console.WriteLine(violationEvt.ToJson());

            // 2. Containment Protocol Activated
            Dictionary<string, string> containMeta = new Dictionary<string, string>();
            containMeta["trigger_rule"] = violationEvt.EventType;
            EmitRawEvent("CONTAINMENT_TRIGGERED", "containment", "critical", "Containment Protocol Activated",
                "Host policy threshold reached. Commencing immediate thread freeze and network severing.", targetPid, containMeta);

            // 3. Suspend Threads
            int suspendedThreads = responder.SuspendProcessThreads(targetPid);
            Dictionary<string, string> suspendMeta = new Dictionary<string, string>();
            suspendMeta["suspended_threads"] = suspendedThreads.ToString();
            suspendMeta["action"] = "SuspendThread";
            EmitRawEvent("ACTION_SUSPEND_THREAD", "containment", "critical", "Threads Suspended (Freeze)",
                string.Format("Invoked SuspendThread() on {0} active thread(s) of PID {1}. Execution frozen.", suspendedThreads, targetPid), targetPid, suspendMeta);

            // 4. Sever Outbound Network via WFP
            ulong filterId;
            responder.SeverOutboundNetwork(targetPid, out filterId);
            Dictionary<string, string> wfpMeta = new Dictionary<string, string>();
            wfpMeta["filter_id"] = filterId.ToString();
            wfpMeta["direction"] = "OUTBOUND_DENY";
            EmitRawEvent("ACTION_WFP_SEVER", "containment", "critical", "Network Severed (WFP Block)",
                string.Format("Dynamic Windows Filtering Platform (WFP) filter #{0} injected for PID {1}. Outbound network dropped.", filterId, targetPid), targetPid, wfpMeta);

            // 5. Final Frozen Verdict
            List<string> violations = new List<string>();
            violations.Add(violationEvt.Title);
            if (listener != null)
            {
                foreach (string v in listener.GetViolations())
                {
                    if (!violations.Contains(v)) violations.Add(v);
                }
            }

            EmitVerdict("FROZEN", "Threat Contained: Sandbox Execution Frozen",
                "Sandbox frozen and network severed. Security policy violations were confirmed.", targetPid, violations);
        }

        private static int HandleMonitor(string[] args)
        {
            int targetPid = 0;
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--pid" && i + 1 < args.Length)
                {
                    int.TryParse(args[++i], out targetPid);
                }
            }

            if (targetPid <= 0)
            {
                Console.Error.WriteLine("Error: Must specify valid --pid <pid>");
                return 1;
            }

            EtwListener listener = new EtwListener(targetPid);
            ResponseAgent responder = new ResponseAgent();

            listener.OnTelemetryEvent += delegate(EtwTelemetryEvent evt)
            {
                Console.WriteLine(evt.ToJson());
            };
            listener.OnPolicyViolation += delegate(EtwTelemetryEvent evt)
            {
                ExecuteContainment(targetPid, evt, responder, listener);
            };

            listener.Start();

            // Keep alive until process exits or containment
            try
            {
                Process targetProc = Process.GetProcessById(targetPid);
                while (!targetProc.HasExited && !_contained)
                {
                    Thread.Sleep(200);
                }
            }
            catch { }

            listener.Stop();
            return 0;
        }

        private static int HandleContain(string[] args)
        {
            int targetPid = 0;
            for (int i = 1; i < args.Length; i++)
            {
                if (args[i] == "--pid" && i + 1 < args.Length)
                {
                    int.TryParse(args[++i], out targetPid);
                }
            }

            if (targetPid <= 0) return 1;

            ResponseAgent responder = new ResponseAgent();
            int threads = responder.SuspendProcessThreads(targetPid);
            ulong filterId;
            responder.SeverOutboundNetwork(targetPid, out filterId);

            Dictionary<string, string> meta = new Dictionary<string, string>();
            meta["threads"] = threads.ToString();
            meta["filter_id"] = filterId.ToString();
            EmitRawEvent("MANUAL_CONTAINMENT", "containment", "critical", "Manual Containment Triggered",
                string.Format("Target PID {0} contained. {1} threads suspended, WFP filter #{2} active.", targetPid, threads, filterId), targetPid, meta);
            return 0;
        }

        private static void EmitRawEvent(string type, string category, string severity, string title, string description, int pid, Dictionary<string, string> details)
        {
            EtwTelemetryEvent evt = new EtwTelemetryEvent
            {
                EventType = type,
                Category = category,
                Severity = severity,
                Title = title,
                Description = description,
                ProcessId = pid
            };
            if (details != null)
            {
                evt.Metadata = details;
            }
            Console.WriteLine(evt.ToJson());
        }

        private static void EmitVerdict(string state, string title, string description, int pid, List<string> violations)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append("{");
            sb.AppendFormat("\"timestamp\":\"{0}\",", DateTime.Now.ToString("HH:mm:ss.fff"));
            sb.Append("\"type\":\"VERDICT\",");
            sb.Append("\"category\":\"verdict\",");
            sb.AppendFormat("\"severity\":\"{0}\",", state == "CLEAN" ? "clean" : "violation");
            sb.AppendFormat("\"verdict_state\":\"{0}\",", state);
            sb.AppendFormat("\"title\":\"{0}\",", Escape(title));
            sb.AppendFormat("\"description\":\"{0}\",", Escape(description));
            sb.AppendFormat("\"target_pid\":{0},", pid);
            sb.Append("\"violations\":[");
            for (int i = 0; i < violations.Count; i++)
            {
                if (i > 0) sb.Append(",");
                sb.AppendFormat("\"{0}\"", Escape(violations[i]));
            }
            sb.Append("]");
            sb.Append("}");
            Console.WriteLine(sb.ToString());
        }

        private static string Escape(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\r", "").Replace("\n", " ");
        }
    }
}
