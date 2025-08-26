using System;
using System.Collections.Generic;
using System.Reflection;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.Json.Nodes;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.IO.Compression;
using System.Xml.Linq;

namespace OAB
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Show("=====================================");
            Show("  Welcome to Oman Arab Bank Oab Ipay v-2.1");
            Show("=====================================");

        }


        public static void Show(string message)
        {
            Console.WriteLine(message);
        }
    }

}
