using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Net.Http;
using System.Net;
using Microsoft.AspNetCore.Http;
using NetworkMonitor.Objects;
using System.Web;

namespace NetworkMonitor.Utils.Helpers
{
   public static class EncryptHelper
{
    
         public static string? DecryptedPassword(string key,string? password)
        {
            if (password != null)
            {
                return AesOperation.DecryptString(key, password);
            }
            else
            {
                return null;
            }

        }
        public static string? EncryptedPassword(string key, string? password)
        {
            if (password != null)
            {
                password = AesOperation.EncryptString(key, password);
                return password;
            }
            else
            {
                return password;
            }
        }

         public static string EncryptStrUrlCoded(string emailEncryptKey, string str)
        {
            str = AesOperation.EncryptString(emailEncryptKey, str);
            return HttpUtility.UrlEncode(str);
        }
        public static bool IsBadKey(string emailEncryptKey, string encryptedStr, string checkStr)
        {
            string decryptString="";
            if (encryptedStr == "") return true;
            try
            {
                decryptString = AesOperation.DecryptString(emailEncryptKey, encryptedStr);
            }
            catch
            {
                return true;
            }
            return !decryptString.Equals(checkStr);
        }
    }
}

    
    
       