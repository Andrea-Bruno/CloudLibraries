﻿using System;
using System.Collections.ObjectModel;
using System.ComponentModel;
using CloudSync;

namespace CloudBox
{
    /// <summary>
    /// Class to manage a list of file transfers, providing functionality to update and limit the preserved elements.
    /// </summary>
    public class FileTransferList : ObservableCollection<FileTransferList.FileTransfer>
    {
        /// <summary>
        /// Instantiate a list to store and view a log of file transfer operations
        /// </summary>
        /// <param name="preservedElements">// Puts a limit on the preserved elements</param>
        public FileTransferList(int preservedElements = 128)
        {
            PreservedElements = preservedElements;
        }

        /// <summary>
        /// Update the list with a new file transfer operation
        /// </summary>
        /// <param name="fileTransfer">File transfer operation</param>
        public void UpdateList(Sync.FileTransfer fileTransfer)
        {
            var file = new FileTransfer(fileTransfer);
            lock (this)
            {
                FileTransfer inProgress = null;
                foreach (var item in this)
                {
                    if (item.Hash == file.Hash && !item.Completed)
                    {
                        inProgress = item;
                        break;
                    }
                }
                if (inProgress != null)
                {
                    if (inProgress.Part != file.Part)
                    {
                        inProgress.Part = file.Part;
                        inProgress.OnPropertyChanged(nameof(FileTransfer.Part));
                    }
                    if (inProgress.Total != file.Total)
                    {
                        inProgress.Total = file.Total;
                        inProgress.OnPropertyChanged(nameof(fileTransfer.Total));
                    }
                    if (inProgress.Name != file.Name)
                    {
                        inProgress.Name = file.Name;
                        inProgress.OnPropertyChanged(nameof(fileTransfer.Name));
                    }
                    OnUpdated?.Invoke(IndexOf(inProgress)); // Generate an event to warn that a record has changed, and send the address of the changed record
                }
                else
                {
                    Insert(0, file);
                    if (Count > PreservedElements) // Puts a limit on the preserved elements
                        RemoveAt(Count - 1);
                    OnUpdated?.Invoke(-1); // Generates an event to notify that a new item has been added to the list
                }
            }
        }

        /// <summary>
        /// Puts a limit on the preserved elements
        /// </summary>
        public readonly int PreservedElements; 

        /// <summary>
        /// Event (It is actually an Action to avoid creating multiple links from web page instances) that is raised when the list is updated: Returns the index of the record that has changed, or -1 if a new record has been added at the beginning.
        /// This event must be used only by UIs that do not support the ObservableCollection and therefore need this event to update.
        /// </summary>
        public Action<int> OnUpdated;

        /// <summary>
        /// Class representing a file transfer operation
        /// </summary>
        public class FileTransfer : Sync.FileTransfer, INotifyPropertyChanged
        {
            /// <summary>
            /// Initialize a new instance of the FileTransfer class
            /// </summary>
            /// <param name="fileTransfer">File transfer operation</param>
            public FileTransfer(Sync.FileTransfer fileTransfer)
            {
                IsUpload = fileTransfer.IsUpload;
                Hash = fileTransfer.Hash;
                Part = fileTransfer.Part;
                Total = fileTransfer.Total;
                Name = fileTransfer.Name;
                Length = fileTransfer.Length;
            }

            /// <summary>
            /// Label indicating whether the transfer is an upload or download
            /// </summary>
            public string TransferLaberl => IsUpload ? "Upload" : "Download";

            /// <summary>
            /// Represents the method that will handle the property changed event raised when a property is changed on a component.
            /// </summary>
            public event PropertyChangedEventHandler PropertyChanged;

            /// <summary>
            /// Method to raise the property changed event
            /// </summary>
            /// <param name="propertyName">Name of the property that changed</param>
            internal void OnPropertyChanged(string propertyName) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
