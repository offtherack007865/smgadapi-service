using System;
using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Web;

namespace ADAPI.Utilities
{
    public static class ExtensionTools
    {
        /// <summary>
        /// Takes the string file and gets the values by each char. then after it is done, disposes of the string so that all references to it in memory are gone.
        /// </summary>
        /// <param name="input"></param>
        /// <returns>SecureString</returns>
        internal static SecureString ToSecureString(this string input)
        {
            SecureString secure = new SecureString();
            foreach (char c in input)
            {
                secure.AppendChar(c);
            }
            secure.MakeReadOnly();
            return secure;
        }
    }
}