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

    private readonly string _gatewayZtIp;
    private readonly int _gatewayPort;
    private readonly int _connectTimeoutSeconds;

    private readonly SemaphoreSlim _connLimit;

    public Socks5Server(
        IPAddress listenIp,
        int listenPort,
        string gatewayZtIp,
        int gatewayPort,
        int connectTimeoutSeconds = 10,
        int maxConcurrentClients = 512)
    {
        _listenIp = listenIp;
        _listenPort = listenPort;
        _gatewayZtIp = gatewayZtIp;
        _gatewayPort = gatewayPort;
        _connectTimeoutSeconds = connectTimeoutSeconds;
        _connLimit = new SemaphoreSlim(maxConcurrentClients, maxConcurrentClients);
    }

    public void Run()
    {
        var listener = new TcpListener(_listenIp, _listenPort);
        listener.Start(backlog: 128);
        Console.WriteLine($"SOCKS5 listening on {_listenIp}:{_listenPort}");
        Console.WriteLine($"ZT gateway: {_gatewayZtIp}:{_gatewayPort} (via libzt)");

        while (true)
        {
            var client = listener.AcceptTcpClient();
            client.NoDelay = true;
            Task.Run(() => HandleClientWithLimit(client));
        }
    }

    private void HandleClientWithLimit(TcpClient client)
    {
        _connLimit.Wait();
        try { HandleClient(client); }
        finally { _connLimit.Release(); }
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
                ReadExact(cs, nMethods);
                cs.Write(new byte[] { 0x05, 0x00 }, 0, 2);

                // ---- REQUEST ----
                byte[] hdr = ReadExact(cs, 4);
                if (hdr[0] != 0x05) return;
                byte cmd = hdr[1];
                byte atyp = hdr[3];

                if (cmd != 0x01)
                {
                    Reply(cs, rep: 0x07);
                    return;
                }

                string host;
                IPAddress dstIp = null;

                if (atyp == 0x01)
                {
                    byte[] ipb = ReadExact(cs, 4);
                    dstIp = new IPAddress(ipb);
                    host = dstIp.ToString();
                }
                else if (atyp == 0x03)
                {
                    int len = cs.ReadByte();
                    if (len <= 0) return;
                    byte[] hb = ReadExact(cs, len);
                    host = Encoding.ASCII.GetString(hb);
                }
                else
                {
                    Reply(cs, rep: 0x08);
                    return;
                }

                byte[] portb = ReadExact(cs, 2);
                int dstPort = (portb[0] << 8) | portb[1];

                Console.WriteLine($"CONNECT {host}:{dstPort} (ATYP={atyp})");

                // ---- CONNECT to Gateway via libzt (ALWAYS) ----
                zfd = Libzt.zts_socket(Libzt.ZTS_AF_INET, Libzt.ZTS_SOCK_STREAM, 0);
                if (zfd < 0)
                {
                    Reply(cs, rep: 0x01);
                    return;
                }

                int rc = Libzt.zts_connect(zfd, _gatewayZtIp, (ushort)_gatewayPort, _connectTimeoutSeconds);
                if (rc < 0)
                {
                    Reply(cs, rep: 0x05);
                    return;
                }

                // Send length-prefixed hello to avoid desync:
                SendTunnelHello(zfd, atyp, host, dstIp, dstPort);

                Reply(cs, rep: 0x00);

                Relay(client, cs, zfd);
            }
            catch (IOException)
            {
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

    private static void SendTunnelHello(int zfd, byte atyp, string host, IPAddress dstIp, int dstPort)
    {
        // FRAME:
        // MAGIC 'ZTF1' (4)
        // LEN uint16 BE (2) = payload length
        // PAYLOAD:
        //   ATYP (1)
        //   (IPv4: 4 bytes) or (DOMAIN: LEN(1)+HOST)
        //   PORT uint16 BE (2)

        byte[] payload;
        using (var ms = new MemoryStream())
        {
            ms.WriteByte(atyp);

            if (atyp == 0x01)
            {
                byte[] ipb = dstIp.GetAddressBytes();
                if (ipb.Length != 4) throw new InvalidOperationException("IPv4 required");
                ms.Write(ipb, 0, 4);
            }
            else if (atyp == 0x03)
            {
                byte[] hb = Encoding.ASCII.GetBytes(host);
                if (hb.Length <= 0 || hb.Length > 255) throw new InvalidOperationException("Invalid host length");
                ms.WriteByte((byte)hb.Length);
                ms.Write(hb, 0, hb.Length);
            }
            else
            {
                throw new InvalidOperationException("Unsupported ATYP");
            }

            ms.WriteByte((byte)((dstPort >> 8) & 0xff));
            ms.WriteByte((byte)(dstPort & 0xff));

            payload = ms.ToArray();
        }

        if (payload.Length > 0xFFFF) throw new InvalidOperationException("Payload too large");

        byte[] header = new byte[6];
        header[0] = (byte)'Z'; header[1] = (byte)'T'; header[2] = (byte)'F'; header[3] = (byte)'1';
        header[4] = (byte)((payload.Length >> 8) & 0xff);
        header[5] = (byte)(payload.Length & 0xff);

        ZtWriteAll(zfd, header, 0, header.Length);
        ZtWriteAll(zfd, payload, 0, payload.Length);
    }

    private static void Relay(TcpClient client, NetworkStream clientStream, int zfd)
    {
        var cts = new CancellationTokenSource();

        var t1 = Task.Run(() => ClientToZt(clientStream, zfd, cts.Token));
        var t2 = Task.Run(() => ZtToClient(clientStream, zfd, cts.Token));

        Task.WaitAny(t1, t2);

        cts.Cancel();
        try { client.Client.Shutdown(SocketShutdown.Both); } catch { }
        try { client.Close(); } catch { }

        // Let the read side observe close; don't double-close too aggressively.
        try { Libzt.zts_close(zfd); } catch { }

        Task.WaitAll(new[] { t1, t2 }, millisecondsTimeout: 2000);
    }

    private static void ClientToZt(NetworkStream cs, int zfd, CancellationToken ct)
    {
        byte[] buf = new byte[16 * 1024];

        while (!ct.IsCancellationRequested)
        {
            int n;
            try { n = cs.Read(buf, 0, buf.Length); }
            catch { break; }

            if (n <= 0) break;

            try
            {
                ZtWriteAll(zfd, buf, 0, n);
            }
            catch
            {
                break;
            }
        }
    }

    private static void ZtToClient(NetworkStream cs, int zfd, CancellationToken ct)
    {
        byte[] buf = new byte[16 * 1024];

        while (!ct.IsCancellationRequested)
        {
            int r;
            try { r = Libzt.zts_read(zfd, buf, buf.Length); }
            catch { break; }

            if (r <= 0) break;

            try { cs.Write(buf, 0, r); }
            catch { break; }
        }
    }

    // Robust zts_write without offset support in native API: copy chunks and write until complete.
    private static void ZtWriteAll(int zfd, byte[] src, int offset, int len)
    {
        int off = offset;
        int remaining = len;

        while (remaining > 0)
        {
            int take = Math.Min(16 * 1024, remaining);

            var chunk = new byte[take];
            Buffer.BlockCopy(src, off, chunk, 0, take);

            int sent = 0;
            while (sent < take)
            {
                int w = Libzt.zts_write(zfd, chunk, take - sent);
                if (w <= 0) throw new IOException("zts_write failed");

                if (w < (take - sent))
                {
                    // compact remaining bytes to the beginning of chunk
                    Buffer.BlockCopy(chunk, w, chunk, 0, (take - sent) - w);
                }

                sent += w;
            }

            off += take;
            remaining -= take;
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
        resp[3] = 0x01;
        s.Write(resp, 0, resp.Length);
    }
}

internal static class Program
{
    static int Main(string[] args)
    {
        // socks5 <config_path> <nwid_hex> <listen_ip> <listen_port> <gateway_zt_ip> <gateway_port>
        if (args.Length != 6)
        {
            Console.WriteLine("Usage: socks5 <config_path> <nwid_hex> <listen_ip> <listen_port> <gateway_zt_ip> <gateway_port>");
            return 1;
        }

        string configPath = args[0];
        ulong netId = Convert.ToUInt64(args[1], 16);
        IPAddress listenIp = IPAddress.Parse(args[2]);
        int listenPort = int.Parse(args[3]);
        string gatewayZtIp = args[4];
        int gatewayPort = int.Parse(args[5]);

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

        new Socks5Server(listenIp, listenPort, gatewayZtIp, gatewayPort).Run();
        return 0;
    }
}