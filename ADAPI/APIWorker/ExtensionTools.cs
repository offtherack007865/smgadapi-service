using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web;

namespace ADAPI.APIWorker
{
    internal static class ExtensionTools
    {
        /// <summary>
        /// Removes HTML out of the reply.
        /// </summary>
        /// <param name="value"></param>
        /// <returns></returns>
        internal static string RemoveHtml(this string value)
        {
            string result = Regex.Replace(value, @"<[^>]*(>|$)|&nbsp;|&zwnj;|&raquo;|&laquo;", string.Empty).Trim();

            return result;
        }

    }
}