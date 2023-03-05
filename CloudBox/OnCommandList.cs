using System;
using System.Collections.Generic;
using CloudSync;

namespace CloudBox
{
    /// <summary>
    /// Class to log the sequence of commands that are executed
    /// </summary>
    public class OnCommandList : List<OnCommand>
    {
        /// <summary>
        /// Initializer
        /// </summary>
        /// <param name="preservedElements">Number of elemento to keep in the list</param>
        public OnCommandList(int preservedElements = 16)
        {
            PreservedElement = preservedElements;
        }
        /// <summary>
        /// Number of items to preserve in the list (adding more will remove the last ones)
        /// </summary>
        public int PreservedElement;
        /// <summary>
        /// Element that is invoked every time the list is updated
        /// </summary>
        public Sync.OnCommandEventHandler OnCommandEvent;
        /// <summary>
        /// Add an item to the list
        /// </summary>
        /// <param name="command"></param>
        /// <param name="userId"></param>
        /// <param name="isOutput"></param>
        public void AddOnCommand(Sync.Commands command, ulong? userId, bool isOutput)
        {
            lock (this)
            {
                var OnCommand = new OnCommand(command, userId, isOutput);
                Insert(0, OnCommand);
                if (Count > PreservedElement)
                {
                    RemoveAt(Count - 1);
                }
            }
            OnCommandEvent?.Invoke(command, userId, isOutput);
        }
    }
    /// <summary>
    /// Command registered in the log list
    /// </summary>
    public class OnCommand
    {
        /// <summary>
        /// Initializer
        /// </summary>
        /// <param name="command">Command</param>
        /// <param name="userId">Id of sende user</param>
        /// <param name="isOutput">True if is a command output, false if is command in input</param>
        public OnCommand(Sync.Commands command, ulong? userId, bool isOutput)
        {
            Command = command;
            UserId = userId;
            IsOutput = isOutput;
        }
        /// <summary>
        /// Command
        /// </summary>
        public readonly Sync.Commands Command;
        /// <summary>
        /// Date and time of command execution
        /// </summary>
        public readonly DateTime Time = DateTime.UtcNow;
        /// <summary>
        /// Id of sender user
        /// </summary>
        public readonly ulong? UserId;
        /// <summary>
        /// True if is a command output, false if is command in input
        /// </summary>
        public readonly bool IsOutput;
        /// <summary>
        /// True if is a command input, false if is command in output
        /// </summary>
        public bool IsInput => !IsInput;
    }

}
