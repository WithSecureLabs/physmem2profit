using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;

namespace Physmem2profit
{
    class DriverService
    {
        #region WinAPI imports
        [DllImport("advapi32", EntryPoint = "OpenSCManagerW", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
        protected static extern IntPtr OpenSCManager(string machineName, string databaseName, uint dwAccess);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Auto)]
        protected static extern IntPtr CreateService(IntPtr hSCManager, string lpServiceName, string lpDisplayName, uint dwDesiredAccess, uint dwServiceType, uint dwStartType, uint dwErrorControl,
            string lpBinaryPathName, string lpLoadOrderGroup, string lpdwTagId, string lpDependencies, string lpServiceStartName, string lpPassword);

        [DllImport("kernel32", SetLastError = true)]
        protected static extern int CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, uint lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes,
            uint hTemplateFile);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Auto)]
        protected static extern IntPtr OpenService(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        protected static extern bool StartService(IntPtr hService, int dwNumServiceArgs, string[] lpServiceArgVectors);

        [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
        protected static extern unsafe bool QueryServiceStatusEx(IntPtr serviceHandle, int infoLevel, IntPtr buffer, int bufferSize, out int bytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        protected static extern int ControlService(IntPtr serviceHandle, ServiceControl controlCode, SERVICE_STATUS lpServiceStatus);

        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        protected static extern bool DeleteService(IntPtr hService);

        [DllImport("advapi32", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        protected static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("kernel32", ExactSpelling = true, SetLastError = true, CharSet = CharSet.Auto)]
        protected static extern bool DeviceIoControl(IntPtr hDevice, uint dwIoControlCode, byte[] inBuffer, uint nInBufferSize, byte[] lpOutBuffer, uint nOutBufferSize,
            ref uint lpBytesReturned, IntPtr lpOverlapped);

        [DllImport("kernel32", SetLastError = true)]
        protected static extern bool SetFilePointerEx(IntPtr hFile, long liDistanceToMove, IntPtr lpNewFilePointer, uint dwMoveMethod);

        [DllImport("kernel32", SetLastError = true)]
        protected static extern bool ReadFile(IntPtr hFile, [Out] byte[] lpBuffer, uint nNumberOfBytesToRead, out uint lpNumberOfBytesRead, IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        protected static extern bool CloseHandle(IntPtr hObject);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        protected struct SERVICE_STATUS_PROCESS
        {
            public int serviceType;
            public int currentState;
            public int controlsAccepted;
            public int win32ExitCode;
            public int serviceSpecificExitCode;
            public int checkPoint;
            public int waitHint;
            public int processID;
            public int serviceFlags;
        }

        protected enum ServiceState
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007,
        }

        /// A few access rights for use throughout the code.
        [Flags]
        protected enum AccessRights : uint
        {
            SERVICE_ERROR_IGNORE = 0x00000000,
            SERVICE_KERNEL_DRIVER = 0x00000001,
            SC_MANAGER_CREATE_SERVICE = 0x00002,
            SERVICE_DEMAND_START = 0x00000003,
            SC_MANAGER_ALL_ACCESS = 0xF003F,
            SERVICE_ALL_ACCESS = 0xF01FF,
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            FILE_SHARE_READ = 0x00000001,
            FILE_SHARE_WRITE = 0x00000002
        }

        public enum ServiceControl
        {
            Stop = 0x00000001,
            Pause = 0x00000002,
            Continue = 0x00000003,
            Interrogate = 0x00000004,
            Shutdown = 0x00000005,
            ParamChange = 0x00000006,
            NetBindAdd = 0x00000007,
            NetBindRemove = 0x00000008,
            NetBindEnable = 0x00000009,
            NetBindDisable = 0x0000000A
        }

        [StructLayout(LayoutKind.Sequential)]
        protected class SERVICE_STATUS
        {
            public int dwServiceType = 0;
            public ServiceState dwCurrentState = 0;
            public int dwControlsAccepted = 0;
            public int dwWin32ExitCode = 0;
            public int dwServiceSpecificExitCode = 0;
            public int dwCheckPoint = 0;
            public int dwWaitHint = 0;
        }

        protected IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        #endregion WinAPI imports

        /// <summary>
        /// A RAII wrapper for native service-related handles.
        /// </summary>
        class ServiceHandle
        {
            public IntPtr Handle;

            public ServiceHandle() => Handle = IntPtr.Zero;

            public ServiceHandle(IntPtr handle) => Handle = handle;

            public bool IsSet
            {
                get { return Handle != IntPtr.Zero; }
            }

            public void Close()
            {
                if (IsSet)
                    CloseServiceHandle(Handle);

                Handle = IntPtr.Zero;
            }

            ~ServiceHandle()
            {
                Close();
            }
        }

        #region Member fields
        private ServiceHandle _handle = new ServiceHandle();
        private ServiceHandle _hScManager = new ServiceHandle();
        private string _serviceName;
        #endregion Member fields

        /// <summary>
        /// Public constructor
        /// </summary>
        /// <param name="serviceName">Name of the service. Used both as full name and display name.</param>
        public DriverService(string serviceName) => _serviceName = serviceName;

        /// <summary>
        /// Opens driver service or creates one if it doesn't exist.
        /// </summary>
        /// <param name="pathToDriver">Relative or absolute path to the driver.</param>
        protected void OpenOrCreate(string pathToDriver)
        {
            // Check if service handle is already set.
            if (_handle.IsSet)
            {
                Program.Log("Service already opened.", Program.LogMessageSeverity.Warning);
                return;
            }

            // Grab a handle to the service manager.
            _hScManager = new ServiceHandle(OpenSCManager(null, null, (uint)AccessRights.SC_MANAGER_ALL_ACCESS));
            if (!_hScManager.IsSet)
                ThrowWin32Exception("Failed to get handle to SC Manager.");

            // Check if service already exists.
            _handle = new ServiceHandle(OpenService(_hScManager.Handle, _serviceName, (uint)AccessRights.SERVICE_ALL_ACCESS));
            if (_handle.IsSet)
            {
                Program.Log("Service " + _serviceName + " already exists.", Program.LogMessageSeverity.Warning);
                return;
            }

            // It doesn't - create it. First check if provided driver file exists.
            Program.Log("Creating service " + _serviceName + "...");
            if (!File.Exists(pathToDriver))
                throw new Exception("Driver file does not exist.");

            _handle = new ServiceHandle(CreateService(_hScManager.Handle, _serviceName, _serviceName, (uint) AccessRights.SERVICE_ALL_ACCESS, (uint) AccessRights.SERVICE_KERNEL_DRIVER,
                (uint) AccessRights.SERVICE_DEMAND_START, (uint) AccessRights.SERVICE_ERROR_IGNORE, Path.GetFullPath(pathToDriver), null, null, null, null, null));
            if (!_handle.IsSet)
                ThrowWin32Exception("Failed to create service.");
        }

        /// <summary>
        /// Deletes the service.
        /// </summary>
        protected void Delete()
        {
            if (!DeleteService(_handle.Handle))
                ThrowWin32Exception("Failed to delete service.");

            _handle.Close();
            _hScManager.Close();
        }

        /// <summary>
        /// Starts the driver service.
        /// </summary>
        protected void Start()
        {
            // Sanity check.
            if (!_handle.IsSet)
                throw new ArgumentNullException("Cannot start a service that was not open.");

            // Check service status.
            switch (QueryServiceStatus(_handle.Handle).currentState)
            {
                case (int)ServiceState.SERVICE_RUNNING:
                    Program.Log("Service already running.", Program.LogMessageSeverity.Warning);
                    return;

                case (int)ServiceState.SERVICE_STOPPED:
                    Program.Log("Service is stopped. Trying to start it...");
                    break;

                case (int)ServiceState.SERVICE_START_PENDING:
                    Program.Log("Service is in a start-pending state.", Program.LogMessageSeverity.Warning);
                    return;

                case (int)ServiceState.SERVICE_STOP_PENDING:
                    Program.Log("Service is in a stop-pending state. Trying to start it...", Program.LogMessageSeverity.Warning);
                    break;

                case (int)ServiceState.SERVICE_CONTINUE_PENDING:
                    Program.Log("Service is in a continue-pending state. ", Program.LogMessageSeverity.Warning);
                    return;

                case (int)ServiceState.SERVICE_PAUSE_PENDING:
                    Program.Log("Service is in a pause-pending state. Trying to start it...", Program.LogMessageSeverity.Warning);
                    break;

                case (int)ServiceState.SERVICE_PAUSED:
                    Program.Log("Service is paused. Trying to start it...", Program.LogMessageSeverity.Warning);
                    break;
            }

            // Try and start the service.
            if (!StartService(_handle.Handle, 0, null))
                ThrowWin32Exception("Service Failed to start.");
        }

        /// <summary>
        /// Stops the driver service.
        /// </summary>
        protected void Stop()
        {
            // Sanity check.
            if (!_handle.IsSet)
                throw new ArgumentNullException("Cannot stop a service that was not open.");

            // Check service status.
            switch (QueryServiceStatus(_handle.Handle).currentState)
            {
                case (int)ServiceState.SERVICE_STOPPED:
                    Program.Log("Service already stopped.", Program.LogMessageSeverity.Warning);
                    return;

                case (int)ServiceState.SERVICE_RUNNING:
                    Program.Log("Service is running. Trying to stop it...");
                    break;

                case (int)ServiceState.SERVICE_START_PENDING:
                    Program.Log("Service is in a start-pending state. Trying to stop it...", Program.LogMessageSeverity.Warning);
                    break;

                case (int)ServiceState.SERVICE_STOP_PENDING:
                    Program.Log("Service is in a stop-pending state.", Program.LogMessageSeverity.Warning);
                    return;

                case (int)ServiceState.SERVICE_CONTINUE_PENDING:
                    Program.Log("Service is in a continue-pending state. Trying to stop it...", Program.LogMessageSeverity.Warning);
                    break;

                case (int)ServiceState.SERVICE_PAUSE_PENDING:
                    Program.Log("Service is in a pause-pending state. Trying to stop it...", Program.LogMessageSeverity.Warning);
                    break;

                case (int)ServiceState.SERVICE_PAUSED:
                    Program.Log("Service is paused. Trying to stop it...", Program.LogMessageSeverity.Warning);
                    break;
            }

            // Try and stop the service.
            SERVICE_STATUS status = new SERVICE_STATUS();
            if (ControlService(_handle.Handle, ServiceControl.Stop, status) == 0)
                ThrowWin32Exception("Service Failed to stop.");
        }

        /// <summary>
        /// Calls native QueryServiceStatusEx function and returns service status.
        /// </summary>
        /// <param name="serviceHandle">handle to service to query status of.</param>
        /// <returns>Service status value.</returns>
        private static SERVICE_STATUS_PROCESS QueryServiceStatus(IntPtr serviceHandle)
        {
            unsafe
            {
                IntPtr pData = IntPtr.Zero;
                try
                {
                    // Allocate memory for the call.
                    pData = Marshal.AllocHGlobal(sizeof(SERVICE_STATUS_PROCESS));

                    // Check and return status.
                    if (!QueryServiceStatusEx(serviceHandle, 0, pData, sizeof(SERVICE_STATUS_PROCESS), out _))
                        ThrowWin32Exception("QueryServiceStatusEx failed.");

                    return (SERVICE_STATUS_PROCESS) Marshal.PtrToStructure(pData, typeof(SERVICE_STATUS_PROCESS));
                }
                finally
                {
                    // Deallocate global memory.
                    if (pData != IntPtr.Zero)
                        Marshal.FreeHGlobal(pData);
                }
            }
        }

        /// <summary>
        /// A handy function that calls GetLastError then throws an Exception that contains that error code, description and an optional message.
        /// </summary>
        /// <param name="operationDescription">Optional description of an action that resulted with exception being thrown.</param>
        public static void ThrowWin32Exception(string operationDescription)
            => throw new Exception(operationDescription + " " + Marshal.GetLastWin32Error() + ": "+ new Win32Exception(Marshal.GetLastWin32Error()).Message);
    }
}
