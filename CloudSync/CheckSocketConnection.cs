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
                using (var client = new TcpClient())
                    return client.ConnectAsync(ip.ToString(), port).Wait(500);
                       
            }
            catch (SocketException)
            {
            }
            return false;
        }
    }
}
