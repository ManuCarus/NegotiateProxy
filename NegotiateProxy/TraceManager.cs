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
using System.IO;

namespace NegotiateProxy
{
    public sealed class TraceManager
    {
        // verbose mode
        public enum VerboseMode { None = 0, Verbose = 1, VeryVerbose = 2, VeryVeryVerbose = 3 };

        // private 
        private VerboseMode verboseMode = VerboseMode.None;
        private TextWriter textWriter = Console.Out;
        private bool noConsole = false;

        // constants
        private byte cLineLength = 80;

        // ctor
        public TraceManager(VerboseMode verboseMode, TextWriter textWriter, bool noConsole)
        {
            this.verboseMode = verboseMode;
            this.textWriter = textWriter;
            this.noConsole = noConsole;
        }

        // verbose tracer
        public void TraceLine(string line, VerboseMode verbose)
        {
            if (String.IsNullOrEmpty(line)) return;
            if (TraceAllowed(verbose)) this.WriteLine(line);
        }

        public void Trace(string line, VerboseMode verbose)
        {
            if (String.IsNullOrEmpty(line)) return;
            if (TraceAllowed(verbose)) this.Write(line);
        }

        public void TraceSeparator(char line, VerboseMode verbose)
        {
            if (TraceAllowed(verbose)) this.WriteLine(line.ToString().PadRight(cLineLength, line));
        }

        public void TraceLine(VerboseMode verbose)
        {
            if (TraceAllowed(verbose)) this.WriteLine(); 
        }

        private bool TraceAllowed(VerboseMode verbose)
        {
            int maximalVerboseValue = (int)verboseMode;
            int verboseModeValue = (int)verbose;

            return (verboseModeValue <= maximalVerboseValue);
        }

        // always write to file _and_ to console
        private void WriteLine(string line)
        {
            this.textWriter.WriteLine(line);
            if (!this.textWriter.Equals(Console.Out) && !this.noConsole) Console.Out.WriteLine(line);
        }

        private void WriteLine()
        {
            this.textWriter.WriteLine();
            if (!this.textWriter.Equals(Console.Out) && !this.noConsole) Console.Out.WriteLine();
        }

        private void Write(string line)
        {
            this.textWriter.Write(line);
            if (!this.textWriter.Equals(Console.Out) && !this.noConsole) Console.Out.Write(line);
        }
    }
}
