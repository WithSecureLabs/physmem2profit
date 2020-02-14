using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace Physmem2profit
{
    /// <summary>
    /// Application class.
    /// </summary>
    public class Program
    {
        // Global settings for the whole application.
        internal static class Settings
        {
            // Remember to initialize all settings with default values.
            public static bool HideConsole = false;
            public static bool VerboseMode = false;
            public static IPAddress ListeningIp = IPAddress.Parse("127.0.0.1");
            public static UInt16 ListeningPort = 8080;

            /// <summary>
            /// Parses CL into application settings.
            /// </summary>
            /// <param name="commandLineArguments"></param>
            public static void Parse(string[] commandLineArguments)
            {
                for (int i = 0; i < commandLineArguments.Length; i++)
                    if (commandLineArguments[i] == "-p" || commandLineArguments[i] == "--port")
                    {
                        if (++i == commandLineArguments.Length)
                            throw new ArgumentException("No port number for -p/--port CL switch provided.");
                        else if (!UInt16.TryParse(commandLineArguments[i], out ListeningPort))
                            throw new ArgumentException("Couldn't parse port number for -p/--port CL switch.");
                    }
                    else if (commandLineArguments[i] == "-i" || commandLineArguments[i] == "--ip")
                    {
                        if (++i == commandLineArguments.Length)
                            throw new ArgumentException("No IP number for -i/--ip CL switch provided.");
                        else if (!IPAddress.TryParse(commandLineArguments[i], out ListeningIp))
                            throw new ArgumentException("Couldn't parse IP number for -i/--ip CL switch.");
                    }
                    else if (commandLineArguments[i] == "-v" || commandLineArguments[i] == "--verbose")
                        Settings.VerboseMode = true;
                    else if (commandLineArguments[i] == "-h" || commandLineArguments[i] == "--hidden")
                        HideConsole = true;
            }
        }

        #region WinAPI imports
        /// <summary>
        /// An import used to control visibility of the console window.
        /// </summary>
        /// <returns></returns>
        [DllImport("user32.dll")]
        private static extern int ShowWindow(int Handle, int showState);

        /// <summary>
        /// An import used to control visibility of the console window.
        /// </summary>
        /// <returns></returns>
        [DllImport("kernel32.dll")]
        public static extern int GetConsoleWindow();

        /// <summary>
        /// The server object.
        /// </summary>
        internal static Physerver Server = null;
        #endregion WinAPI imports

        /// <summary>
        /// Enumeration type used for logging runtime messages.
        /// </summary>
        internal enum LogMessageSeverity
        {
            Information,                                                                            ///< For typical/debug message.
            Success,                                                                                ///< Indicates a successful action.
            Warning,                                                                                ///< An important information.
            Error                                                                                   ///< Indicates a failed action.
        }

        /// <summary>
        /// Logs a single runtime message.
        /// </summary>
        /// <param name="message">message to log.</param>
        /// <param name="severity">type of the message.</param>
        internal static void Log(String message, LogMessageSeverity severity = LogMessageSeverity.Information)
        {
            // Choose the right style for provided severity.
            string severityCharacter = "?";
            switch (severity)
            {
                case LogMessageSeverity.Success:
                    Console.ForegroundColor = ConsoleColor.Green;
                    severityCharacter = "+";
                    break;

                case LogMessageSeverity.Error:
                    Console.ForegroundColor = ConsoleColor.Red;
                    severityCharacter = "-";
                    break;

                case LogMessageSeverity.Warning:
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    severityCharacter = "?";
                    break;

                default:
                    Console.ForegroundColor = ConsoleColor.White;
                    severityCharacter = "*";
                    break;
            }

            // Show the message.
            Console.WriteLine("[" + severityCharacter + "] " + message);
        }

        /// <summary>
        /// Application entry point.
        /// </summary>
        /// <param name="args">Application command-line arguments</param>
        /// <returns>0 if no error occurred.</returns>
        public static int Main(string[] args)
        {
            // Store unmodified console window style.
            var previousConsoleStyle = Console.ForegroundColor;

            // Register a handler that restores console colors back in case of Ctrl+C being hit.
            Console.CancelKeyPress += delegate { Console.ForegroundColor = previousConsoleStyle; };

            // Warn early if not elevated.
            if (!(new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator))
                Log("Run in a context of a non-elevated user.", LogMessageSeverity.Warning);

            try
            {
                // Process CL arguments.
                Settings.Parse(args);

                // Show console if requested.
                if (Settings.HideConsole)
                    ShowWindow(GetConsoleWindow(), 0);

                Program.Log("Registering driver bridges.");
                var receivers = GatherCommandReceivers();

                // Start listening.
                Server = new Physerver(Settings.ListeningIp, Settings.ListeningPort, receivers);
                Server.Listen();
                return 0;
            }
            catch (Win32Exception exception)
            {
                Log(exception.ErrorCode.ToString() + ": " + exception.Message, LogMessageSeverity.Error);
            }
            catch (Exception exception)
            {
                Log(exception.Message, LogMessageSeverity.Error);
            }
            finally
            {
                // Set back the default console window style.
                Console.ForegroundColor = previousConsoleStyle;
                Console.WriteLine();
            }

            return -1;
        }

        /// <summary>
        /// Uses reflection to enumerates all commands receivers.
        /// </summary>
        /// <returns>A dictionary of all receivers and their commands.</returns>
        private static Dictionary<ICommandReceiver, List<MethodInfo>> GatherCommandReceivers()
        {
            // Use reflection to enlist all receivers and their commands.
            var retDicionary = new Dictionary<ICommandReceiver, List<MethodInfo>>();
            foreach (Type type in AppDomain.CurrentDomain.GetAssemblies().SelectMany(s => s.GetTypes()).Where(p => typeof(ICommandReceiver).IsAssignableFrom(p) && p.IsClass && !p.IsAbstract))
                try
                {
                    Program.Log("Found driver bridge: " + type.Name + ".", Program.LogMessageSeverity.Success);
                    var commands = type.GetMethods().Where(y => y.GetCustomAttributes(typeof(Command), true).Length > 0).ToList();

                    // Log all registered commands.
                    foreach (var cmd in commands)
                        Program.Log("   Registered command: " + cmd.Name + ".", Program.LogMessageSeverity.Success);

                    retDicionary.Add(Activator.CreateInstance(type) as ICommandReceiver, commands);
                }
                catch (Exception exception)
                {
                    Program.Log("Couldn't register driver bridge: " + type.Name + ". " + exception.Message, Program.LogMessageSeverity.Error);
                }

            // Return everything we've found.
            return retDicionary;
        }
    }
}
