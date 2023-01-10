using System;
using System.Collections.Generic;
using CloudSync;

namespace CloudBox
{
    public class OnCommandList : List<OnCommand>
    {
        public OnCommandList(int preservedElements = 16)
        {
            PreservedElement = preservedElements;
        }
        public readonly int PreservedElement;
        public Sync.OnCommandEventHandler OnCommandEvent;

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
    public class OnCommand
    {
        public OnCommand(Sync.Commands command, ulong? userId, bool isOutput)
        {
            Command = command;
            UserId = userId;
            IsOutput = isOutput;
        }
        public readonly Sync.Commands Command;
        public readonly DateTime Time = DateTime.UtcNow;
        public readonly ulong? UserId;
        public readonly bool IsOutput;
        public bool IsInput => !IsInput;
    }

}
