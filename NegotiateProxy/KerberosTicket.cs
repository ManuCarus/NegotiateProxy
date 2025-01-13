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

namespace NegotiateProxy
{
    class KerberosTicket
    {
        private string httpHeaderAuthorization = String.Empty;
        private DateTime validTo = DateTime.MinValue;

        internal bool IsValid()
        {
            return ((httpHeaderAuthorization != null) && (httpHeaderAuthorization.Length > 0) && (DateTime.Now <= validTo));
        }

        internal string Ticket
        {
            get { return httpHeaderAuthorization; }
            set { httpHeaderAuthorization = value; }
        }

        internal DateTime ValidTo
        {
            get { return validTo; }
            set { validTo = value; }
        }
    }
}
