// ZtGatewayForwarder.cs
// Build: .NET Framework 4.7.2
using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

internal sealed class ZtGatewayForwarder
{
    private readonly IPAddress _listenIp;
    private readonly int _listenPort;

    public ZtGatewayForwarder(IPAddress listenIp, int listenPort)
    {
        _listenIp = listenIp;
        _listenPort = listenPort;
    }

    public void Run()
    {
        var listener = new TcpListener(_listenIp, _listenPort);
        listener.Start(backlog: 256);
        Console.WriteLine($"ZT Gateway Forwarder listening on {_listenIp}:{_listenPort}");

        while (true)
        {
            var c = listener.AcceptTcpClient();
            c.NoDelay = true;
            Task.Run(() => HandleClientAsync(c));
        }
    }

    private async Task HandleClientAsync(TcpClient tunnelClient)
    {
        using (tunnelClient)
        using (var ts = tunnelClient.GetStream())
        {
            TcpClient outClient = null;
            try
            {
                var req = ReadHelloFrame(ts);

                Console.WriteLine($"TUNNEL CONNECT -> {req.Host}:{req.Port} (ATYP={req.Atyp})");

                outClient = new TcpClient();
                outClient.NoDelay = true;
                awaitConnect(outClient, req.Host, req.Port, timeoutMs: 10000);

                using (outClient)
                using (var os = outClient.GetStream())
                {
                    await RelayAsync(tunnelClient, ts, outClient, os).ConfigureAwait(false);
                }
            }
            catch (EndOfStreamException)
            {
            }
            catch (InvalidDataException ide)
            {
                Console.WriteLine("Forwarder protocol error: " + ide.Message);
            }
            catch (TimeoutException te)
            {
                Console.WriteLine("Forwarder error: " + te.Message);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Forwarder error: " + ex.Message);
            }
            finally
            {
                try { outClient?.Close(); } catch { }
            }
        }
    }

    private static async Task RelayAsync(
        TcpClient tunnelClient,
        NetworkStream tunnel,
        TcpClient outboundClient,
        NetworkStream outbound)
    {
        using (var cts = new CancellationTokenSource())
        {
            Task t1 = PumpAsync(tunnelClient, tunnel, outboundClient, outbound, cts.Token);
            Task t2 = PumpAsync(outboundClient, outbound, tunnelClient, tunnel, cts.Token);

            await Task.WhenAny(t1, t2).ConfigureAwait(false);
            cts.Cancel();

            // 让双方尽量“温和”结束：不要立刻 Close() 两边，给 TLS 等协议排空的机会
            await Task.WhenAll(
                t1.ContinueWith(_ => { }, TaskScheduler.Default),
                t2.ContinueWith(_ => { }, TaskScheduler.Default)).ConfigureAwait(false);

            try { tunnelClient.Close(); } catch { }
            try { outboundClient.Close(); } catch { }
        }
    }

    private static async Task PumpAsync(
        TcpClient srcClient,
        NetworkStream src,
        TcpClient dstClient,
        NetworkStream dst,
        CancellationToken ct)
    {
        byte[] buf = new byte[16 * 1024];

        try
        {
            while (!ct.IsCancellationRequested)
            {
                int n = await src.ReadAsync(buf, 0, buf.Length, ct).ConfigureAwait(false);
                if (n <= 0)
                {
                    // 对端正常结束写入 -> 半关闭发送端，让另一侧还能把剩余数据读完
                    try { dstClient.Client.Shutdown(SocketShutdown.Send); } catch { }
                    break;
                }

                await dst.WriteAsync(buf, 0, n, ct).ConfigureAwait(false);
                await dst.FlushAsync(ct).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch
        {
            // 出错时也尽量半关闭
            try { dstClient.Client.Shutdown(SocketShutdown.Send); } catch { }
        }
    }

    private sealed class Hello
    {
        public byte Atyp;
        public string Host;
        public int Port;
    }

    private static Hello ReadHelloFrame(Stream s)
    {
        // MAGIC(4) + LEN(2) + PAYLOAD(LEN)
        byte[] hdr = ReadExact(s, 6);
        if (hdr[0] != (byte)'Z' || hdr[1] != (byte)'T' || hdr[2] != (byte)'F' || hdr[3] != (byte)'1')
            throw new InvalidDataException("Bad magic");

        int len = (hdr[4] << 8) | hdr[5];
        if (len <= 0 || len > 4096) throw new InvalidDataException("Bad payload length");

        byte[] payload = ReadExact(s, len);
        int p = 0;

        byte atyp = payload[p++];

        string host;
        if (atyp == 0x01)
        {
            if (p + 4 > payload.Length) throw new InvalidDataException("Bad IPv4 payload");
            host = new IPAddress(new byte[] { payload[p], payload[p + 1], payload[p + 2], payload[p + 3] }).ToString();
            p += 4;
        }
        else if (atyp == 0x03)
        {
            if (p >= payload.Length) throw new InvalidDataException("Bad domain payload");
            int hlen = payload[p++];
            if (hlen <= 0 || p + hlen > payload.Length) throw new InvalidDataException("Bad domain length");
            host = Encoding.ASCII.GetString(payload, p, hlen);
            p += hlen;
        }
        else
        {
            throw new InvalidDataException("Unsupported ATYP");
        }

        if (p + 2 > payload.Length) throw new InvalidDataException("Missing port");
        int port = (payload[p] << 8) | payload[p + 1];
        p += 2;

        if (p != payload.Length) throw new InvalidDataException("Trailing bytes in hello");

        return new Hello { Atyp = atyp, Host = host, Port = port };
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

    private static void awaitConnect(TcpClient c, string host, int port, int timeoutMs)
    {
        var ar = c.BeginConnect(host, port, null, null);
        if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
            throw new TimeoutException("Connect timeout");
        c.EndConnect(ar);
    }
}

internal static class Program
{
    static int Main(string[] args)
    {
        // forwarder <listen_ip> <listen_port>
        if (args.Length != 2)
        {
            Console.WriteLine("Usage: forwarder <listen_ip> <listen_port>");
            return 1;
        }

        IPAddress ip = IPAddress.Parse(args[0]);
        int port = int.Parse(args[1]);

        new ZtGatewayForwarder(ip, port).Run();
        return 0;
    }
}