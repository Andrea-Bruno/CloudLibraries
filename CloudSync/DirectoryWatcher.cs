using System;
using System.IO;
using System.Threading;

namespace CloudSync
{
    public class DirectotyWatcher
    {

        private readonly FileSystemWatcher fileSystemWatcher;

        public DirectotyWatcher(string directoryToWatch)
        {

            fileSystemWatcher = new FileSystemWatcher(directoryToWatch);
            fileSystemWatcher.EnableRaisingEvents = true;

            fileSystemWatcher.Created += Created;
            fileSystemWatcher.Changed += Changed;
            fileSystemWatcher.Deleted += Deleted;
            fileSystemWatcher.Renamed += Renamed;

        } // end FileInputMonitor()

        private void Created(object sender, FileSystemEventArgs e)
        {
            ProcessFile(Event.Created, e.FullPath);
        }
        private void Changed(object sender, FileSystemEventArgs e)
        {
            ProcessFile(Event.Changed, e.FullPath);
        }
        private void Deleted(object sender, FileSystemEventArgs e)
        {
            ProcessFile(Event.Deleted, e.FullPath);
        }
        private void Renamed(object sender, FileSystemEventArgs e)
        {
            ProcessFile(Event.Renamed, e.FullPath);
        }

        private enum Event
        {
            Created,
            Changed,
            Deleted,
            Renamed,
        }
        private void ProcessFile(Event @event, string fileName)
        {
            FileStream inputFileStream;
            while (true)
            {
                try
                {
                    inputFileStream = new FileStream(fileName,
                        FileMode.Open, FileAccess.ReadWrite);
                    var reader = new StreamReader(inputFileStream);
                    Console.WriteLine(reader.ReadToEnd());
                    // Break out from the endless loop
                    break;
                }
                catch (IOException)
                {
                    // Sleep for 3 seconds before trying
                    Thread.Sleep(3000);
                } // end try
            } // end while(true)
        } // end private void ProcessFile(String fileName)

    }

}
