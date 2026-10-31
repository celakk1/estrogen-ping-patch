using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

[assembly: DefaultDllImportSearchPaths(DllImportSearchPath.System32)]

public static class NativeMtuLabDevice
{
    const uint DICD_GENERATE_ID = 1;
    const uint DIF_REGISTERDEVICE = 25;
    const uint DIF_REMOVE = 5;
    const uint SPDRP_HARDWAREID = 1;
    const uint INSTALLFLAG_NONINTERACTIVE = 4;
    const uint DI_NEEDRESTART = 0x80;
    const uint DI_NEEDREBOOT = 0x100;
    static readonly Guid netClass = new Guid("4d36e972-e325-11ce-bfc1-08002be10318");
    static readonly HashSet<string> ownedIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

    [StructLayout(LayoutKind.Sequential)]
    struct DeviceInfo { public uint cbSize; public Guid classGuid; public uint devInst; public IntPtr reserved; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct InstallParams
    {
        public uint cbSize, flags, flagsEx;
        public IntPtr hwndParent, installMsgHandler, installMsgHandlerContext, fileQueue;
        public UIntPtr classInstallReserved;
        public uint reserved;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string driverPath;
    }

    [DllImport("setupapi.dll", ExactSpelling = true, SetLastError = true)]
    static extern IntPtr SetupDiCreateDeviceInfoList(ref Guid classGuid, IntPtr hwndParent);
    [DllImport("setupapi.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiCreateDeviceInfoW(IntPtr set, string name, ref Guid classGuid, string description, IntPtr hwndParent, uint flags, ref DeviceInfo info);
    [DllImport("setupapi.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiSetDeviceRegistryPropertyW(IntPtr set, ref DeviceInfo info, uint property, byte[] data, uint length);
    [DllImport("setupapi.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool SetupDiCallClassInstaller(uint function, IntPtr set, ref DeviceInfo info);
    [DllImport("setupapi.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiGetDeviceInstanceIdW(IntPtr set, ref DeviceInfo info, StringBuilder id, uint size, out uint needed);
    [DllImport("setupapi.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiGetDeviceInstallParamsW(IntPtr set, ref DeviceInfo info, ref InstallParams parameters);
    [DllImport("setupapi.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool SetupDiOpenDeviceInfoW(IntPtr set, string id, IntPtr hwndParent, uint flags, ref DeviceInfo info);
    [DllImport("setupapi.dll", ExactSpelling = true, SetLastError = true)]
    static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("newdev.dll", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool UpdateDriverForPlugAndPlayDevicesW(IntPtr hwndParent, string hardwareId, string infPath, uint flags, out bool reboot);

    static void check(bool result, string operation)
    {
        if (!result)
        {
            int code = Marshal.GetLastWin32Error();
            throw new Win32Exception(code, operation + " failed with Win32 " + code + ": " + new Win32Exception(code).Message);
        }
    }

    static void requireNoReboot(IntPtr set, ref DeviceInfo info)
    {
        var parameters = new InstallParams { cbSize = (uint)Marshal.SizeOf(typeof(InstallParams)) };
        check(SetupDiGetDeviceInstallParamsW(set, ref info, ref parameters), "Read disposable device installation flags");
        if ((parameters.flags & (DI_NEEDRESTART | DI_NEEDREBOOT)) != 0) throw new InvalidOperationException("Disposable loopback installation requires a reboot; no reboot will be requested.");
    }

    public static string create()
    {
        var classGuid = netClass;
        var set = SetupDiCreateDeviceInfoList(ref classGuid, IntPtr.Zero);
        if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        string ownedId = null;
        bool registered = false;
        var info = new DeviceInfo { cbSize = (uint)Marshal.SizeOf(typeof(DeviceInfo)) };
        try
        {
            check(SetupDiCreateDeviceInfoW(set, "Net", ref classGuid, "estrogen ping patch disposable MTU lab adapter", IntPtr.Zero, DICD_GENERATE_ID, ref info), "Create disposable root device");
            var hardwareId = Encoding.Unicode.GetBytes("*msloop\0\0");
            check(SetupDiSetDeviceRegistryPropertyW(set, ref info, SPDRP_HARDWAREID, hardwareId, (uint)hardwareId.Length), "Set fixed Microsoft loopback hardware ID");
            check(SetupDiCallClassInstaller(DIF_REGISTERDEVICE, set, ref info), "Register disposable loopback device");
            registered = true;
            var id = new StringBuilder(512);
            uint needed;
            check(SetupDiGetDeviceInstanceIdW(set, ref info, id, (uint)id.Capacity, out needed), "Read newly created device identity");
            ownedId = id.ToString();
            ownedIds.Add(ownedId);
            requireNoReboot(set, ref info);
            var infPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "INF", "netloop.inf");
            bool reboot;
            check(UpdateDriverForPlugAndPlayDevicesW(IntPtr.Zero, "*msloop", infPath, INSTALLFLAG_NONINTERACTIVE, out reboot), "Install built-in Microsoft loopback driver without UI");
            if (reboot) throw new InvalidOperationException("Disposable loopback installation requested a reboot.");
            requireNoReboot(set, ref info);
            return ownedId;
        }
        catch (Exception error)
        {
            try
            {
                if (ownedId != null) remove(ownedId);
                else if (registered) check(SetupDiCallClassInstaller(DIF_REMOVE, set, ref info), "Remove newly registered device after identity-read failure");
            }
            catch (Exception cleanupError) { throw new AggregateException("Loopback creation and owned-device cleanup failed.", error, cleanupError); }
            throw;
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
    }

    public static void remove(string instanceId)
    {
        if (!ownedIds.Contains(instanceId)) throw new InvalidOperationException("Refusing to remove a device not created by this lab process.");
        var classGuid = netClass;
        var set = SetupDiCreateDeviceInfoList(ref classGuid, IntPtr.Zero);
        if (set == new IntPtr(-1)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try
        {
            var info = new DeviceInfo { cbSize = (uint)Marshal.SizeOf(typeof(DeviceInfo)) };
            check(SetupDiOpenDeviceInfoW(set, instanceId, IntPtr.Zero, 0, ref info), "Open owned disposable device for removal");
            check(SetupDiCallClassInstaller(DIF_REMOVE, set, ref info), "Remove owned disposable loopback device");
            ownedIds.Remove(instanceId);
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
    }
}
