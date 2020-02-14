using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Text;
using System.Threading;

namespace Physmem2profit
{
    /// <summary>
    /// A simple TCP Server used for communication.
    /// </summary>
    internal class Physerver
    {
        /// <summary>
        /// Thread of a connected client.
        /// </summary>
        protected Thread _ClientThread = null;

        /// <summary>
        /// Sockets listener used for communication.
        /// </summary>
        private TcpListener _TcpListener;

        /// <summary>
        /// Container for all receivers (drivers) and their commands.
        /// </summary>
        private Dictionary<ICommandReceiver, List<MethodInfo>> _Receivers;

        /// <summary>
        /// Public constructor.
        /// </summary>
        /// <param name="ip">Address to listen for commands on.</param>
        /// <param name="tcpPort">TCP port used to listen for commands.</param>
        /// <param name="receivers">List of all commands receivers.</param>
        public Physerver(IPAddress ip, UInt16 tcpPort, Dictionary<ICommandReceiver, List<MethodInfo>> receivers)
        {
            // Store receivers.
            _Receivers = receivers;

            Program.Log("Starting server on " + ip.ToString() + ":" + tcpPort + "...");
            _TcpListener = new TcpListener(ip, tcpPort);
            _TcpListener.Start();

            Program.Log("Server Started.", Program.LogMessageSeverity.Success);
        }

        /// <summary>
        /// Listens for remote commands. Main loop of the application.
        /// </summary>
        public void Listen()
        {
            Program.Log("Waiting for a connection...");
            while (true)
                try
                {
                    var clientStream = _TcpListener.AcceptTcpClient().GetStream();

                    // Someone has joined. Create a new thread, but first, check if there is another client connected at the moment and disconnect him.
                    _ClientThread?.Abort();
                    _ClientThread = new Thread(new ThreadStart (delegate { this.HandleSingleClient(clientStream); }));
                    _ClientThread.Start();
                }
                catch (Exception exception)
                {
                    Program.Log(exception.Message, Program.LogMessageSeverity.Error);
                }
        }

        /// <summary>
        /// Main loop of the client's thread.
        /// </summary>
        /// <param name="clientStream">Client's network stream.</param>
        protected void HandleSingleClient(NetworkStream clientStream)
        {
            Program.Log("Connected!", Program.LogMessageSeverity.Success);
            while (true)
                try
                {
                     // Process a single packet.
                    if (!PerformCommand(clientStream))
                        Environment.Exit(1);
                }
                catch (IOException exception)
                {
                    Program.Log(exception.Message, Program.LogMessageSeverity.Error);
                    Program.Log("Disconnecting... Component is still open for another connection.");
                    return;
                }
                catch (ThreadAbortException)
                {
                    Program.Log("New client is about to connect - aborting previous connection.", Program.LogMessageSeverity.Warning);
                    return;
                }
                catch (Exception exception)
                {
                    Program.Log(exception.Message, Program.LogMessageSeverity.Error);
                }
        }

        private static byte[] SubArray(byte[] data, int index, int length)
        {
            var result = new byte[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }

        /// <summary>
        /// Reads and processes a single command.
        /// </summary>
        /// <param name="clientStream">TCP client's NetworkStream object.</param>
        /// <returns>false if program should be terminated</returns>
        private bool PerformCommand(NetworkStream clientStream)
        {
            var packet = ReadPacket(clientStream);
            var nameEnd = Array.IndexOf(packet, (byte) 0x0A);
            if (nameEnd == -1)
                throw new Exception("Wrong packet. Receiver not provided.");

            var commandReceiverName = Encoding.Default.GetString(packet, 0, nameEnd);

            // Check if it's a built-in command.
            if (commandReceiverName == "exit")
            {
                Program.Log("Exit command received. Terminating.", Program.LogMessageSeverity.Information);
                return false;
            }

            // Find command receiver.
            foreach (var receiver in _Receivers)
                if (String.Compare(receiver.Key.GetType().Name, commandReceiverName, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    var methodEnd = Array.IndexOf(packet, (byte) 0x0A, nameEnd + 1);
                    if (methodEnd == -1)
                        throw new Exception("Wrong packet. Method not provided");

                    var command = Encoding.Default.GetString(packet, nameEnd + 1, methodEnd - nameEnd - 1);
                    foreach (var cmd in receiver.Value)
                        if (String.Compare(cmd.Name, command, StringComparison.OrdinalIgnoreCase) == 0)
                        {
                            // Invoke command method.
                            if (Program.Settings.VerboseMode)
                                Program.Log("Invoking Command " + cmd.Name + " for driver " + receiver.Key.GetType().Name + ".");
                            var response = cmd.Invoke(receiver.Key, new object[] { SubArray(packet, methodEnd + 1, packet.Length - methodEnd - 1) }) as byte[];

                            // Send everything what has been returned by the command.
                            if (response == null || response.Length != 0)
                                clientStream.Write(response, 0, response.Length);

                            return true;
                        }

                    Program.Log("Command for driver '" + command + "' not recognized.", Program.LogMessageSeverity.Error);
                    return true;
                }

            Program.Log("Command/driver not recognized: " + commandReceiverName, Program.LogMessageSeverity.Error);
            return true;
        }

        /// <summary>
        /// Reads a fixed number of bytes from network stream.
        /// </summary>
        /// <param name="stream">stream to read bytes from</param>
        /// <param name="length">number of bytes to read</param>
        /// <returns>Buffer of bytes read.</returns>
        private Byte[] ReadFixedNumberOfBytesFromStream(NetworkStream stream, int length)
        {
            // Simply read in a loop until received requested number of bytes.
            Byte[] retBuffer = new Byte[length];
            for (int numBytesRead = 0; numBytesRead < length;)
                numBytesRead += stream.Read(retBuffer, numBytesRead, length - numBytesRead);

            return retBuffer;
        }

        /// <summary>
        /// Reads a single packet from provided network stream.
        /// </summary>
        /// <param name="clientStream">stream to read packet from.</param>
        /// <returns>Read packet.</returns>
        private byte[] ReadPacket(NetworkStream clientStream)
        {
            // Read length of the packet.
            int packetLength = BitConverter.ToInt32(ReadFixedNumberOfBytesFromStream(clientStream, 4), 0);
            // Read and return the packet.
            return ReadFixedNumberOfBytesFromStream(clientStream, packetLength);
        }
    }
}
