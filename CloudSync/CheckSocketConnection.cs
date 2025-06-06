using System.Net.Sockets;

namespace CloudSync
{
    public static partial class Util
    {
        static public bool IsPortReachable(int port, bool fromPublicIp = true)
        {
            try
            {
                var ip = fromPublicIp ? GetPublicIpAddress() : GetLocalIpAddress();
                using var client = new TcpClient
                {
                    LingerState = new LingerOption(true, 0), // Close the connection immediately after the Close() method
                    NoDelay = true, // Reduces latency
                };
                return client.ConnectAsync(ip.ToString(), port).Wait(500);
            }
            catch (SocketException)
            {
            }
            return false;
        }
    }
}
