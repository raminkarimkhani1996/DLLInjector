using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace dll_injector
{
    
    class Program
    {
        static readonly IntPtr INTPTR_ZERO = (IntPtr)0;

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr address_of_allocated_memory, IntPtr dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttribute, IntPtr dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
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
        const int MEM_COMMIT = 0x1000;
        const int PAGE_READWRITE = 0x00000004;
        static void Main(string[] args)
        {
            header();
            if (args.Length==0)
            {
                Console.WriteLine("dll_injector.exe <PROCESS_ID> <DLL_PATH>");
                Console.WriteLine("");
                Console.WriteLine("Example");
                Console.WriteLine("dll_injector.exe 1815 C:\\test.dll");
                Console.ForegroundColor = ConsoleColor.White;
                Environment.Exit(0);
            }
            else
            {
                if (uint.TryParse(args[0], out uint processID))
                {
                    Console.WriteLine("Process ID:" + processID);
                    Console.WriteLine("DLL Path: " + args[1]);
                    injectDll(processID, args[1]);
                }
            }          
            Console.ReadKey();
        }
        static void injectDll(uint processId, string dll_path)
        {
            ProcessAccessFlags PROCESS_ALL_ACCESS = ProcessAccessFlags.All;
            IntPtr handled_process = OpenProcess(PROCESS_ALL_ACCESS, false, processId);

            if (handled_process == INTPTR_ZERO)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] The process could not be handled");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[+] The process was handled");
            }

            IntPtr address_of_load_library = GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

            if (address_of_load_library == INTPTR_ZERO)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] LoadLibraryA could not be loaded.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[+] LoadLibraryA library loaded");
            }

            IntPtr address_of_allocated_memory = VirtualAllocEx(handled_process, (IntPtr)0, (IntPtr)dll_path.Length + 1, MEM_COMMIT, PAGE_READWRITE);

            if (address_of_allocated_memory == INTPTR_ZERO)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Virtual memory space could not be allocated.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[+] Virtual memory allocated");
            }

            byte[] bytes = Encoding.ASCII.GetBytes(dll_path);

            if (WriteProcessMemory(handled_process, address_of_allocated_memory, bytes, (uint)bytes.Length, 0) == 0)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] The DLL could not be written to the process memory.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[+] The DLL was written to process memory");
            }

            if (CreateRemoteThread(handled_process, (IntPtr)0, (IntPtr)0, address_of_load_library, address_of_allocated_memory, 0, (IntPtr)0) == INTPTR_ZERO)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[-] Thread could not be created.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("[+] Thread created");
            }

            CloseHandle(handled_process);
            Console.ForegroundColor = ConsoleColor.White;
            Environment.Exit(0);
        }
        static void header()
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("DLL INJECTOR - Ramin KARIMKHANI");
            Console.WriteLine("Twitter: @ramin_karimhani");
            Console.WriteLine("");
        }
    }
}