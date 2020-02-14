using System;

namespace Physmem2profit
{
    /// <summary>
    /// An interface used to indicate a type (by inheriting this interface) that is a processor of commands sent by our server.
    /// </summary>
    interface ICommandReceiver
    {
    }

    /// <summary>
    /// An attribute used to indicate a method in ICommandReceiver-inherited class that is a Command. Such methods need to take a single byte[] argument (a collective buffer of parameters
    ///   of the command) and return a byte[] that will be sent back to the connected TCP client or null if there's nothing to send back (to report progress or indicate and error Program.Log
    ///   can be used as well).
    /// </summary>
    /// <example>
    /// class MyCommandReceiver : public ICommandReceiver
    /// {
    ///     [Command]
    ///     void SampleCommand(NetworkStream clientStream, byte[] _)
    ///     {
    ///         Program.Log("SampleCommand called.")
    ///     }
    /// }
    /// </example>
    [AttributeUsage(AttributeTargets.Method)]
    public class Command : Attribute
    {
    }
}
