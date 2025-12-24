// LibztNative.cs
using System;
using System.Runtime.InteropServices;
using System.Text;

internal static class LibztNative
{
    private const string DLL = "libzt.dll"; // 实际可能是 libzt.dll / ZeroTierSockets.dll，按你的文件名改

    // 常量（按 ZeroTierSockets.h / pylon.cpp 使用习惯）
    public const int ZTS_AF_INET = 2;
    public const int ZTS_SOCK_STREAM = 1;

    // errno（可选）
    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_errno();

    // init/start/join
    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_init_from_storage([MarshalAs(UnmanagedType.LPStr)] string path);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern void zts_init_set_event_handler(IntPtr cb); // 先不接事件

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

    // socket I/O
    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_socket(int family, int type, int protocol);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_connect(int fd, [MarshalAs(UnmanagedType.LPStr)] string addr, ushort port, int timeoutSeconds);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_read(int fd, byte[] buf, int len);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_write(int fd, byte[] buf, int len);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern int zts_close(int fd);

    [DllImport(DLL, CallingConvention = CallingConvention.Cdecl)]
    public static extern void zts_util_delay(uint ms);
}