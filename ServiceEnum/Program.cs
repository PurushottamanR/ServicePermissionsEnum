using System;
using System.Collections.Generic;
using System.Text;
using System.ServiceProcess;
using System.Diagnostics;
using Microsoft.Win32;
using System.Threading.Tasks;
using System.Security.Principal;
using System.Security.AccessControl;

namespace ServiceEnum
{
    class Program
    {
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

        static void helpMenu()
        {
            Console.WriteLine();
            Console.WriteLine("ServiceEnum.exe [getservice | getserviceACL] [<name-of-service>]");
            Console.WriteLine();
        }

        static string maskToPermissions(uint accessmasks)
        {
            string permissions = "";
            foreach (uint i in Enum.GetValues(typeof(ServiceAccessFlags)))
            {
                if(Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }

                if (Convert.ToBoolean(i & accessmasks))
                {
                    permissions = permissions + Enum.GetName(typeof(ServiceAccessFlags), i) + " | ";
                    continue;
                }
            }

            return permissions;
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
                uint accessmask = (uint)((CommonAce)rsd.DiscretionaryAcl[i]).AccessMask;
                string permissions = maskToPermissions(accessmask);
                Console.WriteLine("Permissions: {0}", permissions);
                Console.WriteLine();
            }
        }
        static void Main(string[] args)
        {
            if (args.Length > 0)
            {
                string cmd = args[0];
                if (cmd == "getservice")
                {
                    GetServices();
                }
                else if (cmd == "getserviceACL")
                {
                    if (args.Length == 2)
                    {
                        string servicename = args[1];
                        GetServiceAcl(servicename);
                    }

                    else
                    {
                        helpMenu();
                    }
                }
                else
                {
                    helpMenu();
                }
            }
            else
            {
                helpMenu();
            }
        }
    }
}
