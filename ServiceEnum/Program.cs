using System;
using System.Collections.Generic;
using System.Text;
using System.ServiceProcess;
using System.Diagnostics;
using Microsoft.Win32;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Runtime.InteropServices;

namespace ServiceEnum
{
    class Program
    {
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool QueryServiceObjectSecurity(SafeHandle serviceHandle, System.Security.AccessControl.SecurityInfos secInfo, byte[] lpSecDesrBuf, uint bufSize, out uint bufSizeNeeded);
        public enum ServiceAccessFlags : uint
        {
            QueryConfig = 1,
            ChangeConfig = 2,
            QueryStatus = 4,
            EnumerateDependents = 8,
            Start = 16,
            Stop = 32,
            PauseContinue = 64,
            Interrogate = 128,
            UserDefinedControl = 256,
            Delete = 65536,
            ReadControl = 131072,
            WriteDac = 262144,
            WriteOwner = 524288,
            Synchronize = 1048576,
            AccessSystemSecurity = 16777216,
            GenericAll = 268435456,
            GenericExecute = 536870912,
            GenericWrite = 1073741824,
            GenericRead = 2147483648
        }
        static void GetServices()
        {
            ServiceController[] services = ServiceController.GetServices();
            foreach (ServiceController sc in services)
            {
                string servicename = sc.ServiceName;
                string exePath = Registry.GetValue(@"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\" + servicename, "imagePath", string.Empty).ToString();
                Console.WriteLine("Display name: {0}", sc.DisplayName);
                Console.WriteLine("Service name: {0}", sc.ServiceName);
                Console.WriteLine("Service Status: {0}", sc.Status);
                Console.WriteLine("Service binary: {0}", exePath);
                Console.WriteLine();
            }
        }

        static void GetServiceAcl(string servicename)
        {
            ServiceController sc = new ServiceController(servicename);
            Process cmd = new Process();
            cmd.StartInfo.FileName = "sc.exe";
            cmd.StartInfo.Arguments = "sdshow " + servicename;
            cmd.StartInfo.UseShellExecute = false;
            cmd.StartInfo.CreateNoWindow = true;
            cmd.StartInfo.RedirectStandardOutput = true;
            cmd.Start();
            string descriptor = cmd.StandardOutput.ReadToEnd().Trim();
            //Console.WriteLine(descriptor);

            RawSecurityDescriptor rsd = new RawSecurityDescriptor(descriptor);
            Console.WriteLine("ACE count: {0}", rsd.DiscretionaryAcl.Count);
            for(int i = 0; i < rsd.DiscretionaryAcl.Count; i++)
            {
                SecurityIdentifier sid = new SecurityIdentifier(((CommonAce)rsd.DiscretionaryAcl[i]).SecurityIdentifier.Value);
                string accountname = sid.Translate(typeof(NTAccount)).ToString();
                Console.WriteLine("Access type: {0}", ((CommonAce)rsd.DiscretionaryAcl[i]).AceType);
                Console.WriteLine("Identity: {0}", accountname);
                Console.WriteLine("Access Mask: {0}", (ServiceAccessFlags)((CommonAce)rsd.DiscretionaryAcl[i]).AccessMask);
                Console.WriteLine();
            }
        }
        static void Main(string[] args)
        {

            //GetServices();
            GetServiceAcl("bits");

        }
    }
}
