/*
   COPYRIGHT AND PERMISSION NOTICE

   NegotiateProxy - Reverse proxy to handle SPNEGO / Kerberos communication locally and
                    transparently on behalf of client applications that are themselves 
                    not SPNEGO/Kerberos-aware.

   Copyright (c) 2012 by Manu Carus (mailto:manu.carus@ethical-hacking.de)

   The Initial Developer of the Original Code is Manu Carus.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software for any
   purpose, subject to the provisions described below, without fee is
   hereby granted, provided that this entire notice is included in all
   copies of any software that is or includes a copy or modification of
   this software and in all copies of the supporting documentation for
   such software.

   THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
   OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
   FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD-PARTY RIGHTS.
   IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
   DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
   OTHERWISE, ARISING FROM, OUT OF OR INCONNECTION WITH THE SOFTWARE OR THE
   USE OR OTHER DEALINGS IN THE SOFTWARE.

   Except as contained in this notice, the name of a copyright holder shall
   not be used in advertising or otherwise to promote the sale, use or other
   dealings in this Software without prior written permission of the copyright
   holder.
*/

using System;
using System.Collections;
using System.Collections.Specialized;
using System.IO;
using System.Reflection;

namespace NegotiateProxy
{
    public class Program
    {
        public static void Main(string[] args)
        {
            ParameterSet parameterSet = null;
            TraceManager traceManager = null;
            TextWriter logWriter = null;

            try
            {
                // display help if requested
                bool libcurl = true;
                bool quiet = false;
                bool licence = false;
                bool help = true;

                if (args.Length == 0)
                {
                    DisplayHeader();
                    DisplayHelp();
                    Environment.Exit(0);
                }

                if (args.Length > 0)
                {
                    ParameterSet.LookAheadCommandLineParameters(args, out libcurl, out quiet, out licence, out help);
                }

                ICurlController curl = null;
                if (libcurl) curl = new LibCurlController();
                else curl = new CurlController();

                curl.ValidateDependentFiles();

                if (!quiet) DisplayHeader(curl);

                if (licence)
                {
                    DisplayLicence(curl);
                    Environment.Exit(0);
                }

                if (help)
                {
                    DisplayHelp();
                    Environment.Exit(0);
                }

                // create parameter set
                parameterSet = new ParameterSet();

                // parse command line parameters
                parameterSet.ParseCommandLine(args);
                parameterSet.Validate();

                // set verbose level to trace manager
                if (String.IsNullOrEmpty(parameterSet.LogFile))
                {
                    logWriter = Console.Out;
                }
                else
                {
                    StreamWriter sw = new StreamWriter(parameterSet.LogFile, true);
                    sw.AutoFlush = true;
                    logWriter = sw;
                }
                traceManager = new TraceManager(parameterSet.Verbose, logWriter, quiet);

                // do what you're supposed to do...
                ProcessInput(curl, parameterSet, traceManager);

                // flush and close log writer
                logWriter.Flush();
                logWriter.Close();

                // and off you go...
                Environment.Exit(0);
            }
            catch (ArgumentException aex)
            {
                string assemblyVersion;
                string assemblyName;
                GetAssemblyInfo(out assemblyName, out assemblyVersion);
                Console.Out.WriteLine(aex.Message);
                Console.Out.WriteLine();
                Console.Out.WriteLine(String.Format("Try '{0} --help'!", assemblyName));
                Environment.Exit(-1);
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(String.Format("Exception of type '{0}':", ex.GetType().FullName));
                Console.Out.WriteLine(ex.Message);
                if (ex.InnerException != null) Console.Out.WriteLine(ex.InnerException.Message);
                Console.Out.WriteLine();
                Environment.Exit(-1);
            }
            finally
            {
                if (logWriter != null)
                {
                    logWriter.Flush();
                    logWriter.Close();
                }
            }
        }

        private static void DisplayHeader()
        {
            Console.Out.WriteLine("NegotiateProxy - Reverse proxy to handle SPNEGO / Kerberos ");
            Console.Out.WriteLine("                 communication locally and transparently ");
            Console.Out.WriteLine("                 on behalf of client applications that are ");
            Console.Out.WriteLine("                 themselves not SPNEGO/Kerberos-aware.");
            Console.Out.WriteLine();
            Console.Out.WriteLine("Copyright (c) 2012 Manu Carus (mailto:manu.carus@ethical-hacking.de)");
            Console.Out.WriteLine();
        }

        private static void DisplayHeader(ICurlController curl)
        {
            DisplayHeader();

            Console.Out.WriteLine("includes:");
            Console.Out.WriteLine();

            string version = curl.GetVersion();
            Console.Out.WriteLine(version);
            Console.Out.WriteLine();
        }

        private static void DisplayLicence(ICurlController curl)
        {
            NameValueCollection licences = curl.GetLicenceFiles();

            foreach (string licenceItem in licences.Keys)
            {
                string licenceFile = licences[licenceItem];
                DisplayLicence(licenceItem, licenceFile);
            }
        }

        private static void DisplayLicence(string licenceItem, string licenceFile)
        {
            TextReader textReader = null;

            try
            {
                textReader = new StreamReader(licenceFile);
                string licence = textReader.ReadToEnd();

                string headline = String.Format("Licence Terms: {0}", licenceItem);
                string underline = "-".PadRight(headline.Length, '-');

                Console.Out.WriteLine(headline);
                Console.Out.WriteLine(underline);
                Console.Out.WriteLine(licence);
                Console.Out.WriteLine();
            }
            catch (Exception ex)
            {
                Console.Out.WriteLine(ex.Message);
            }
            finally
            {
                if (textReader != null) textReader.Close();
            }
        }

        private static void DisplayHelp()
        {
            string assemblyName = String.Empty;
            string assemblyVersion = string.Empty;
            GetAssemblyInfo(out assemblyName, out assemblyVersion);

            if (String.IsNullOrEmpty(assemblyName)) throw new ArgumentNullException("Couldn't retrieve assembly name!");
            if (String.IsNullOrEmpty(assemblyVersion)) throw new ArgumentNullException("Couldn't retrieve assembly version!");

            Console.Out.WriteLine("Reverse proxy to handle SPNEGO communication according to RfC 4559, 2478, 4178");
            Console.Out.WriteLine("(see http://tools.ietf.org/html/ for details). Use locally to transparently");
            Console.Out.WriteLine("support client applications which are not aware of Kerberos/SPNEGO.");
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("Usage: {0} [<localport>:]<remotehost>[:<remoteport>][:<protocol>] [options]", assemblyName));
            Console.Out.WriteLine(String.Format("   or: {0} [options]", assemblyName));
            Console.Out.WriteLine();
            Console.Out.WriteLine("e.g.");
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("  {0} kerberos.foo.com", assemblyName));
            Console.Out.WriteLine(String.Format("  {0} 8043:kerberos.foo.com:9043:https", assemblyName));
            Console.Out.WriteLine(String.Format("  {0} 8080:kerberos.foo.com:80:http", assemblyName));
            Console.Out.WriteLine();
            Console.Out.WriteLine("Options:");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  -lh,--localhost:<host>          local host to bind to (default: 127.0.0.1)");
            Console.Out.WriteLine("  -lp,--localport:<port>          local port to bind to (default: 6268)");
            Console.Out.WriteLine("  -rh,--remotehost:<host>         remote host to redirect to (mandatory)");
            Console.Out.WriteLine("                                  (allowed values: host name or IP address)");
            Console.Out.WriteLine("  -rp,--remoteport:<port>         remote port to connect to (default: 443)");
            Console.Out.WriteLine("  -p, --protocol:<http[s]>        protocol to use (http or https) (default: https)");
            Console.Out.WriteLine("  -pr,--preauthentication:<sec>   kerberos ticket cache (default: 43200 = 12 hours)");
            Console.Out.WriteLine("  -lc,--libcurl                   use libcurl for Kerberos/Negotiation (default)");
            Console.Out.WriteLine("  -c, --curl                      use curl instead of libcurl for Kerberos/Negotiation");
            Console.Out.WriteLine("  -l, --log:<file>                file to log to (default: stdout)");
            Console.Out.WriteLine("  -v, --verbose                   verbose mode (use multiple times for more details)");
            Console.Out.WriteLine("  -d, --dump                      dump mode (maximum verbose level, acts like -v -v -v)");
            Console.Out.WriteLine("  -q, --quiet                     quiet mode (default: false)");
            Console.Out.WriteLine("  -l, --licence                   displays the terms of licence for this software");
            Console.Out.WriteLine("  -h, --help                      displays this text");
            Console.Out.WriteLine();
            Console.Out.WriteLine("e.g.");
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("  {0} -rh:kerberos.foo.com -p:http", assemblyName));
            Console.Out.WriteLine(String.Format("  {0} -lh:0.0.0.0 -lp:8081 -rh:kerberos.foo.com -rp:80 -v -v", assemblyName));
            Console.Out.WriteLine();
            Console.Out.WriteLine("SSL Options (for --libcurl only):");
            Console.Out.WriteLine();
            Console.Out.WriteLine("  -sv,--ssl-version:<version>     ssl version (default, TLSv1, SSLv3)");
            Console.Out.WriteLine("  -vh,--verify-host:<flag>        0: do not verify host");
            Console.Out.WriteLine("                                  1: check existence");
            Console.Out.WriteLine("                                  2: ensure that it matches the provided hostname (default)");
            Console.Out.WriteLine("  -vp,--no-verify-peer            do not verify the peer's certificate");
            Console.Out.WriteLine("  -ca,--ca-path:<path>            directory holding CA certificates to verify the peer with");
            Console.Out.WriteLine("                                  (must be prepared with the openssl c_rehash utility)");
            Console.Out.WriteLine("                                  (default: .\\certs)");
            Console.Out.WriteLine();
            Console.Out.WriteLine("e.g.");
            Console.Out.WriteLine();
            Console.Out.WriteLine(String.Format("  {0} 8043:kerberos.foo.com:443 --ca-path:C:\\certs", assemblyName));
            Console.Out.WriteLine(String.Format("  {0} 8043:kerberos.foo.com:443 --ssl-version:TLSv1 --verify-host:1 --ca-path:C:\\certs", assemblyName));
            Console.Out.WriteLine();
        }

        private static void GetAssemblyInfo(out string name, out string version)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            AssemblyName assemblyName = assembly.GetName();
            name = assemblyName.Name;
            version = assemblyName.Version.ToString();
        }

        private static void ProcessInput(ICurlController curl, ParameterSet parameterSet, TraceManager traceManager)
        {
            if (parameterSet == null) throw new ArgumentNullException("Invalid argument (parameterSet is missing)!");
            if (traceManager == null) throw new ArgumentNullException("Invalid argument (traceManager is missing)!");

            ReverseProxy reverseProxy = new ReverseProxy(curl, parameterSet, traceManager);
            reverseProxy.Listen();
        }

    }
}
