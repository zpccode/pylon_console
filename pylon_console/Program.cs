// Socks5OverLibzt.cs
// Build: .NET Framework 4.7.2
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

internal static class Libzt
{
    private const string DLL = "libzt.dll";

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int zts_init_from_storage(string path);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_node_start();

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_node_is_online();

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern ulong zts_node_get_id();

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_net_join(ulong netId);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_net_transport_is_ready(ulong netId);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern void zts_util_delay(uint ms);

    public const int ZTS_AF_INET = 2;
    public const int ZTS_SOCK_STREAM = 1;

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_socket(int family, int type, int protocol);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
    public static extern int zts_connect(int fd, string addr, ushort port, int timeoutSeconds);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_read(int fd, byte[] buf, int len);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_write(int fd, byte[] buf, int len);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_close(int fd);
}

internal sealed class Socks5Server
{
    private readonly IPAddress _listenIp;
    private readonly int _listenPort;
    private readonly int _connectTimeoutSeconds;

    // 可选：限制最大并发连接数，避免线程池被打爆
    private readonly SemaphoreSlim _connLimit;

    public Socks5Server(IPAddress listenIp, int listenPort, int connectTimeoutSeconds = 10, int maxConcurrentClients = 512)
    {
        _listenIp = listenIp;
        _listenPort = listenPort;
        _connectTimeoutSeconds = connectTimeoutSeconds;
        _connLimit = new SemaphoreSlim(maxConcurrentClients, maxConcurrentClients);
    }

    public void Run()
    {
        var listener = new TcpListener(_listenIp, _listenPort);
        listener.Start(backlog: 128);
        Console.WriteLine($"SOCKS5 listening on {_listenIp}:{_listenPort}");

        while (true)
        {
            var client = listener.AcceptTcpClient();
            client.NoDelay = true;

            // 多客户端并发：每个连接一个任务
            Task.Run(() => HandleClientWithLimit(client));
        }
    }

    private void HandleClientWithLimit(TcpClient client)
    {
        _connLimit.Wait();
        try
        {
            HandleClient(client);
        }
        finally
        {
            _connLimit.Release();
        }
    }

    private void HandleClient(TcpClient client)
    {
        using (client)
        using (NetworkStream cs = client.GetStream())
        {
            cs.ReadTimeout = Timeout.Infinite;
            cs.WriteTimeout = Timeout.Infinite;

            int zfd = -1;

            try
            {
                // ---- GREETING ----
                int ver = cs.ReadByte();
                if (ver != 0x05) return;

                int nMethods = cs.ReadByte();
                if (nMethods <= 0) return;
                ReadExact(cs, nMethods); // ignore methods

                cs.Write(new byte[] { 0x05, 0x00 }, 0, 2); // NO AUTH

                // ---- REQUEST ----
                byte[] hdr = ReadExact(cs, 4); // VER CMD RSV ATYP
                if (hdr[0] != 0x05) return;
                byte cmd = hdr[1];
                byte atyp = hdr[3];

                if (cmd != 0x01)
                {
                    Reply(cs, rep: 0x07); // Command not supported
                    return;
                }

                string host;
                IPAddress dstIp;

                if (atyp == 0x01) // IPv4
                {
                    byte[] ipb = ReadExact(cs, 4);
                    dstIp = new IPAddress(ipb);
                    host = dstIp.ToString();
                }
                else if (atyp == 0x03) // DOMAIN
                {
                    int len = cs.ReadByte();
                    if (len <= 0) return;
                    byte[] hb = ReadExact(cs, len);
                    host = Encoding.ASCII.GetString(hb);

                    var addrs = Dns.GetHostAddresses(host);
                    dstIp = Array.Find(addrs, a => a.AddressFamily == AddressFamily.InterNetwork);
                    if (dstIp == null)
                    {
                        Reply(cs, rep: 0x08);
                        return;
                    }
                }
                else
                {
                    Reply(cs, rep: 0x08);
                    return;
                }

                byte[] portb = ReadExact(cs, 2);
                int dstPort = (portb[0] << 8) | portb[1];

                Console.WriteLine($"CONNECT {host}:{dstPort} -> {dstIp}");

                // ---- CONNECT via libzt ----
                zfd = Libzt.zts_socket(Libzt.ZTS_AF_INET, Libzt.ZTS_SOCK_STREAM, 0);
                if (zfd < 0)
                {
                    Reply(cs, rep: 0x01);
                    return;
                }

                int rc = Libzt.zts_connect(zfd, dstIp.ToString(), (ushort)dstPort, _connectTimeoutSeconds);
                if (rc < 0)
                {
                    Reply(cs, rep: 0x05);
                    return;
                }

                Reply(cs, rep: 0x00); // success

                // ---- RELAY ----
                Relay(client, cs, zfd);
            }
            catch (IOException)
            {
                // disconnected
            }
            catch (Exception ex)
            {
                Console.WriteLine("Client error: " + ex);
            }
            finally
            {
                if (zfd >= 0)
                {
                    try { Libzt.zts_close(zfd); } catch { }
                }
            }
        }
    }

    private static void Relay(TcpClient client, NetworkStream clientStream, int zfd)
    {
        var cts = new CancellationTokenSource();

        var t1 = Task.Run(() => ClientToZt(clientStream, zfd, cts.Token));
        var t2 = Task.Run(() => ZtToClient(clientStream, zfd, cts.Token));

        Task.WaitAny(t1, t2);

        // 触发双方尽快退出（打断阻塞读）
        cts.Cancel();
        try { client.Client.Shutdown(SocketShutdown.Both); } catch { }
        try { client.Close(); } catch { }
        try { Libzt.zts_close(zfd); } catch { }

        Task.WaitAll(new[] { t1, t2 }, millisecondsTimeout: 2000);
    }

    private static void ClientToZt(NetworkStream cs, int zfd, CancellationToken ct)
    {
        byte[] buf = new byte[16 * 1024];

        while (!ct.IsCancellationRequested)
        {
            int n;
            try
            {
                n = cs.Read(buf, 0, buf.Length);
            }
            catch
            {
                break;
            }

            if (n <= 0) break;

            int off = 0;
            while (off < n && !ct.IsCancellationRequested)
            {
                // libzt 的 zts_write 没有 offset 参数，所以需要拷贝 slice
                int chunkLen = n - off;
                byte[] chunk = new byte[chunkLen];
                Buffer.BlockCopy(buf, off, chunk, 0, chunkLen);

                int w = Libzt.zts_write(zfd, chunk, chunkLen);
                if (w <= 0) return;

                // 如果发生部分写入（w < chunkLen），继续发送剩余部分
                off += w;
            }
        }
    }

    private static void ZtToClient(NetworkStream cs, int zfd, CancellationToken ct)
    {
        byte[] buf = new byte[16 * 1024];

        while (!ct.IsCancellationRequested)
        {
            int r = Libzt.zts_read(zfd, buf, buf.Length);
            if (r <= 0) break;

            try
            {
                cs.Write(buf, 0, r);
                // 一般不需要 Flush；NetworkStream 对 TCP 会直接发
            }
            catch
            {
                break;
            }
        }
    }

    private static byte[] ReadExact(Stream s, int n)
    {
        byte[] b = new byte[n];
        int off = 0;
        while (off < n)
        {
            int r = s.Read(b, off, n - off);
            if (r <= 0) throw new EndOfStreamException();
            off += r;
        }
        return b;
    }

    private static void Reply(Stream s, byte rep)
    {
        byte[] resp = new byte[10];
        resp[0] = 0x05;
        resp[1] = rep;
        resp[2] = 0x00;
        resp[3] = 0x01; // IPv4
        s.Write(resp, 0, resp.Length);
    }
}

internal static class Program
{
    static int Main(string[] args)
    {
        // socks5 <config_path> <nwid_hex> <listen_ip> <listen_port>
        if (args.Length != 4)
        {
            Console.WriteLine("Usage: socks5 <config_path> <nwid_hex> <listen_ip> <listen_port>");
            return 1;
        }

        string configPath = args[0];
        ulong netId = Convert.ToUInt64(args[1], 16);
        IPAddress listenIp = IPAddress.Parse(args[2]);
        int listenPort = int.Parse(args[3]);

        int err = Libzt.zts_init_from_storage(configPath);
        if (err < 0) { Console.WriteLine($"zts_init_from_storage failed: {err}"); return 2; }

        err = Libzt.zts_node_start();
        if (err < 0) { Console.WriteLine($"zts_node_start failed: {err}"); return 3; }

        Console.WriteLine("Waiting for node online...");
        while (Libzt.zts_node_is_online() == 0) Libzt.zts_util_delay(50);
        Console.WriteLine($"Node ID: {Libzt.zts_node_get_id():x}");

        Console.WriteLine($"Joining network {netId:x} ...");
        err = Libzt.zts_net_join(netId);
        if (err < 0) { Console.WriteLine($"zts_net_join failed: {err}"); return 4; }

        Console.WriteLine("Waiting for network transport ready...");
        while (Libzt.zts_net_transport_is_ready(netId) == 0) Libzt.zts_util_delay(50);

        new Socks5Server(listenIp, listenPort).Run();
        return 0;
    }
}