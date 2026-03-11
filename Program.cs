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
using OabIpay_Console;

namespace OAB
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Show("==================================================");
            Show("  Welcome to Oman Arab Bank OAB iPay - Version 2");
            Show("==================================================");
            Show("Branch            : v1.2.0-beta.1");
            Show("Supported .NET    : .NET 8.0");
            Show("Release Date      : 2026-01-07");
            Show("--------------------------------------------------");
            Show("Features in this version:");
            Show("  ✓ 2025-10-07 : JSON-based request and response for payment flow");
            Show("  ✓ 2025-10-07 : Simple signed integration using Terminal credentials (Tranportal ID, Password, Resource Key)");
            Show("  ✓ 2025-10-07 : Inquiry support via Track ID and Transaction ID");
            Show("  ✓ 2025-10-07 : Refund processing using Transaction ID");
            Show("  ✓ 2025-10-07 : Void transaction handling via Transaction ID");
            Show("  ✓ 2025-10-07 : Refund directly to customer's bank account");
            Show("  ✓ 2025-10-10 : Additional User Defined Values included");
            Show("  ✓ 2025-12-24 : Payment callback response now includes masked card number and card type");
            Show("  ✓ 2026-03-11 : Tokenization transaction fix applied.");
            Show("--------------------------------------------------");
            Show("Please use this library to access version 2 features.");
            Show("Ensure all requests and responses follow the new structure.");


        }


        public static void Show(string message)
        {
            Console.WriteLine(message);
        }
    }

}
