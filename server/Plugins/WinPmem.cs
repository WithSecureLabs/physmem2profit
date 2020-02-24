using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Physmem2profit
{
    internal class WinPmem : DriverService, ICommandReceiver
    {
        #region Configuration
        static private readonly string _ServiceName = "physmem2profit";                             ///< Name of the service. Used both as full name and display name.
        static private readonly string _ServiceFileName = @"\\.\pmem";                              ///< Driver communication symbolik link path.
        #endregion Configuration

        #region Constants
        protected static readonly String[] FIELDS = new String[295] { "CR3", "NtBuildNumber", "KernBase", "KDBG", "KPCR00", "KPCR01", "KPCR02", "KPCR03", "KPCR04", "KPCR05", "KPCR06", "KPCR07", "KPCR08", "KPCR09", "KPCR10", "KPCR11", "KPCR12", "KPCR13", "KPCR14", "KPCR15", "KPCR16", "KPCR17", "KPCR18", "KPCR19", "KPCR20", "KPCR21", "KPCR22", "KPCR23", "KPCR24", "KPCR25", "KPCR26", "KPCR27", "KPCR28", "KPCR29", "KPCR30", "KPCR31", "PfnDataBase", "PsLoadedModuleList", "PsActiveProcessHead", "Padding0", "Padding1", "Padding2", "Padding3", "Padding4", "Padding5", "Padding6", "Padding7", "Padding8", "Padding9", "Padding10", "Padding11", "Padding12", "Padding13", "Padding14", "Padding15", "Padding16", "Padding17", "Padding18", "Padding19", "Padding20", "Padding21", "Padding22", "Padding23", "Padding24", "Padding25", "Padding26", "Padding27", "Padding28", "Padding29", "Padding30", "Padding31", "Padding32", "Padding33", "Padding34", "Padding35", "Padding36", "Padding37", "Padding38", "Padding39", "Padding40", "Padding41", "Padding42", "Padding43", "Padding44", "Padding45", "Padding46", "Padding47", "Padding48", "Padding49", "Padding50", "Padding51", "Padding52", "Padding53", "Padding54", "Padding55", "Padding56", "Padding57", "Padding58", "Padding59", "Padding60", "Padding61", "Padding62", "Padding63", "Padding64", "Padding65", "Padding66", "Padding67", "Padding68", "Padding69", "Padding70", "Padding71", "Padding72", "Padding73", "Padding74", "Padding75", "Padding76", "Padding77", "Padding78", "Padding79", "Padding80", "Padding81", "Padding82", "Padding83", "Padding84", "Padding85", "Padding86", "Padding87", "Padding88", "Padding89", "Padding90", "Padding91", "Padding92", "Padding93", "Padding94", "Padding95", "Padding96", "Padding97", "Padding98", "Padding99", "Padding100", "Padding101", "Padding102", "Padding103", "Padding104", "Padding105", "Padding106", "Padding107", "Padding108", "Padding109", "Padding110", "Padding111", "Padding112", "Padding113", "Padding114", "Padding115", "Padding116", "Padding117", "Padding118", "Padding119", "Padding120", "Padding121", "Padding122", "Padding123", "Padding124", "Padding125", "Padding126", "Padding127", "Padding128", "Padding129", "Padding130", "Padding131", "Padding132", "Padding133", "Padding134", "Padding135", "Padding136", "Padding137", "Padding138", "Padding139", "Padding140", "Padding141", "Padding142", "Padding143", "Padding144", "Padding145", "Padding146", "Padding147", "Padding148", "Padding149", "Padding150", "Padding151", "Padding152", "Padding153", "Padding154", "Padding155", "Padding156", "Padding157", "Padding158", "Padding159", "Padding160", "Padding161", "Padding162", "Padding163", "Padding164", "Padding165", "Padding166", "Padding167", "Padding168", "Padding169", "Padding170", "Padding171", "Padding172", "Padding173", "Padding174", "Padding175", "Padding176", "Padding177", "Padding178", "Padding179", "Padding180", "Padding181", "Padding182", "Padding183", "Padding184", "Padding185", "Padding186", "Padding187", "Padding188", "Padding189", "Padding190", "Padding191", "Padding192", "Padding193", "Padding194", "Padding195", "Padding196", "Padding197", "Padding198", "Padding199", "Padding200", "Padding201", "Padding202", "Padding203", "Padding204", "Padding205", "Padding206", "Padding207", "Padding208", "Padding209", "Padding210", "Padding211", "Padding212", "Padding213", "Padding214", "Padding215", "Padding216", "Padding217", "Padding218", "Padding219", "Padding220", "Padding221", "Padding222", "Padding223", "Padding224", "Padding225", "Padding226", "Padding227", "Padding228", "Padding229", "Padding230", "Padding231", "Padding232", "Padding233", "Padding234", "Padding235", "Padding236", "Padding237", "Padding238", "Padding239", "Padding240", "Padding241", "Padding242", "Padding243", "Padding244", "Padding245", "Padding246", "Padding247", "Padding248", "Padding249", "Padding250", "Padding251", "Padding252", "Padding253", "Padding254", "NumberOfRuns" };
        protected static readonly uint INFO_IOCTRL = 0x22C40C;                                      ///< PMem Info control code.
        #endregion Constants

        #region Members
        protected IntPtr _hDevice = IntPtr.Zero;
        protected byte[] _MappingParameters = new byte[3 * sizeof(UInt64)];
        protected List<Tuple<UInt64, UInt64>> _MemoryRuns = new List<Tuple<ulong, ulong>>();
        #endregion Members

        /// <summary>
        /// Public constructor.
        /// </summary>
        public WinPmem() : base(_ServiceName)
        {
        }

        /// <summary>
        /// Installs the PMem driver.
        /// </summary>
        /// <param name="args">relative or absolute path to the pmem driver file</param>
        /// <returns>A buffer containing packet to send.</returns>
        [Command]
        public byte[] Install(byte[] args)
        {
            try
            {
                // Sanity checks.
                string pathToDriver = System.Text.Encoding.UTF8.GetString(args);
                if (pathToDriver.Length == 0)
                    throw new Exception("Wrong usage. Please provide the location of WinPMem driver.");

                Program.Log("Installing service...");
                OpenOrCreate(pathToDriver);
                Program.Log("Service created successfully.", Program.LogMessageSeverity.Success);

                Program.Log("Starting service...");
                Start();
                Program.Log("Driver service started.", Program.LogMessageSeverity.Success);

                // The driver sets up the device object and creates the symbolic link. We just need to grab a handle.
                _hDevice = (System.IntPtr)CreateFile(_ServiceFileName, (uint) AccessRights.GENERIC_READ | (uint) AccessRights.GENERIC_WRITE, (uint) AccessRights.FILE_SHARE_READ |
                   (uint) AccessRights.FILE_SHARE_WRITE, 0, 3, 0, 0);
                if (_hDevice == INVALID_HANDLE_VALUE)
                    throw new Exception("Unable to get a handle to 'pmem' device object.");

                // Create and pass a buffer to the driver. We'll be asking for 102400 / 8(ulong) = 12800 values.
                byte[] mode = { 0x2, 0, 0, 0 }; // ACQUISITION_MODE_PTE_MMAP
                byte[] buffer = new byte[102400];
                uint bytesReturned = 0;
                if (!DeviceIoControl(_hDevice, INFO_IOCTRL, mode, (uint)mode.Length, buffer, (uint)buffer.Length, ref bytesReturned, IntPtr.Zero))
                    ThrowWin32Exception("Sending ParseMemoryRuns control code failed, windows error code");

                // Retrieve all needed parameters.
                Array.Copy(buffer, 0, _MappingParameters, 0, _MappingParameters.Length);
                var numberOfRuns = BitConverter.ToUInt64(buffer, sizeof(UInt64) * (FIELDS.Length - 1));

                _MemoryRuns.Clear();
                // Memory runs pairs are listed after all fields in the buffer.
                for (int offset = FIELDS.Length * sizeof(UInt64), end = offset + Convert.ToInt32(numberOfRuns) * 2 * sizeof(UInt64); offset < end; offset += 2 * sizeof(UInt64))
                    _MemoryRuns.Add(Tuple.Create(BitConverter.ToUInt64(buffer, offset), BitConverter.ToUInt64(buffer, offset + sizeof(UInt64))));

                Program.Log("Successfully installed the WinPMem driver.", Program.LogMessageSeverity.Success);
                return BitConverter.GetBytes(Convert.ToUInt32(0));                                       // Indicates success.
            }
            catch (Exception exception)
            {
                // Show error on screen and send it to the client.
                Program.Log(exception.Message, Program.LogMessageSeverity.Error);
                return BitConverter.GetBytes(Convert.ToUInt32(exception.Message.Length)).Concat(Encoding.UTF8.GetBytes(exception.Message)).ToArray();
            }
        }

        /// <summary>
        /// Uninstalls the PMem driver.
        /// </summary>
        /// <param name="_">Unused</param>
        /// <returns>A buffer containing packet to send.</returns>
        [Command]
        public byte[] Uninstall(byte[] _)
        {
            try
            {
                // Close handle to the device first so the service can be stopped
                CloseHandle(_hDevice);
                Stop();
                Delete();

                Program.Log("Successfully unloaded the WinPMem driver.", Program.LogMessageSeverity.Success);
                return BitConverter.GetBytes(Convert.ToUInt32(0));                                       // Indicates success.
            }
            catch (Exception exception)
            {
                // Show error on screen and send it to the client.
                Program.Log(exception.Message, Program.LogMessageSeverity.Error);
                return BitConverter.GetBytes(Convert.ToUInt32(exception.Message.Length)).Concat(Encoding.UTF8.GetBytes(exception.Message)).ToArray();
            }
        }

        /// <summary>
        /// Sends necessary data to map physical memory as a file system.
        /// </summary>
        /// <param name="clientStream">NetworkStream of a connected TCP client</param>
        /// <param name="_">Unused</param>
        /// <returns>A buffer containing packet to send.</returns>
        [Command]
        public byte[] Map(byte[] _)
        {
            // Build the packet.
            List<byte> packet = new List<byte>(_MappingParameters);

            // Include all runs.
            packet.AddRange(BitConverter.GetBytes(Convert.ToUInt64(_MemoryRuns.Count)));
            foreach (var run in _MemoryRuns)
            {
                packet.AddRange(BitConverter.GetBytes(run.Item1));
                packet.AddRange(BitConverter.GetBytes(run.Item2));
            }

            // Send buffer back to client.
            return packet.ToArray();
        }

        /// <summary>
        /// Reads a memory fragment.
        /// </summary>
        /// <param name="clientStream">NetworkStream of a connected TCP client</param>
        /// <param name="args">offset and length of memory to read</param>
        /// <returns>A buffer containing packet to send.</returns>
        [Command]
        public byte[] Read(byte[] args)
        {
            // We expect args to be 16 bytes: 2 x ulong values.
            if (args.Length != 16)
            {
                Program.Log("Invalid length of arguments.", Program.LogMessageSeverity.Error);
                return null;
            }

            // Set read pointer to specified memory fragment.
            byte[] packet = new byte[BitConverter.ToUInt64(args, 8)];
            if (!SetFilePointerEx(_hDevice, (long)BitConverter.ToUInt64(args, 0), IntPtr.Zero, 0))
                ThrowWin32Exception("Couldn't move file pointer.");

            // Read and return the memory fragment.
            if (!ReadFile(_hDevice, packet, (uint)packet.Length, out uint bytesRead, IntPtr.Zero))
                ThrowWin32Exception("Couldn't read from driver.");
            return packet;
        }
    }
}
