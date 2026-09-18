using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Cerberus.WindowsAgent
{
    /// <summary>
    /// Wraps Windows Job Objects to enforce hard boundaries on CPU, memory,
    /// and child process counts for processes executed inside or alongside the sandbox.
    /// </summary>
    public class JobObjectWrapper : IDisposable
    {
        #region Win32 P/Invoke Definitions

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr lpJobAttributes, string lpName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetInformationJobObject(
            IntPtr hJob,
            JobObjectInfoType JobObjectInformationClass,
            IntPtr lpJobObjectInformation,
            uint cbJobObjectInformationLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool CloseHandle(IntPtr hObject);

        private enum JobObjectInfoType
        {
            BasicLimitInformation = 2,
            BasicUIRestrictions = 4,
            ExtendedLimitInformation = 9,
            CpuRateControlInformation = 15
        }

        [Flags]
        private enum LimitFlags : uint
        {
            JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100,
            JOB_OBJECT_LIMIT_JOB_MEMORY = 0x00000200,
            JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400,
            JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008,
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS
        {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
        {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public LimitFlags LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryLimit;
            public UIntPtr PeakJobMemoryLimit;
        }

        #endregion

        private IntPtr _jobHandle = IntPtr.Zero;
        private bool _disposed = false;

        public JobObjectWrapper(string jobName = null)
        {
            _jobHandle = CreateJobObject(IntPtr.Zero, jobName);
            if (_jobHandle == IntPtr.Zero)
            {
                throw new InvalidOperationException($"Failed to create Job Object. Win32 Error: {Marshal.GetLastWin32Error()}");
            }
        }

        /// <summary>
        /// Configures resource constraints: maximum committed memory limit and active child process ceiling.
        /// </summary>
        public void ApplyLimits(long maxMemoryBytes = 256 * 1024 * 1024, uint maxActiveProcesses = 5)
        {
            if (_jobHandle == IntPtr.Zero) return;

            var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            info.BasicLimitInformation.LimitFlags = LimitFlags.JOB_OBJECT_LIMIT_PROCESS_MEMORY |
                                                    LimitFlags.JOB_OBJECT_LIMIT_JOB_MEMORY |
                                                    LimitFlags.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
                                                    LimitFlags.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            info.ProcessMemoryLimit = new UIntPtr((ulong)maxMemoryBytes);
            info.JobMemoryLimit = new UIntPtr((ulong)maxMemoryBytes);
            info.BasicLimitInformation.ActiveProcessLimit = maxActiveProcesses;

            int length = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr infoPtr = Marshal.AllocHGlobal(length);
            try
            {
                Marshal.StructureToPtr(info, infoPtr, false);
                if (!SetInformationJobObject(_jobHandle, JobObjectInfoType.ExtendedLimitInformation, infoPtr, (uint)length))
                {
                    throw new InvalidOperationException($"SetInformationJobObject failed. Win32 Error: {Marshal.GetLastWin32Error()}");
                }
            }
            finally
            {
                Marshal.FreeHGlobal(infoPtr);
            }
        }

        /// <summary>
        /// Assigns a target process PID to this Job Object.
        /// </summary>
        public bool AssignProcess(int pid)
        {
            using (var process = Process.GetProcessById(pid))
            {
                return AssignProcessToJobObject(_jobHandle, process.Handle);
            }
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                if (_jobHandle != IntPtr.Zero)
                {
                    CloseHandle(_jobHandle);
                    _jobHandle = IntPtr.Zero;
                }
                _disposed = true;
            }
        }
    }
}
