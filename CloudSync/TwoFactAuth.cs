using System.Text;
using System.Security.Cryptography;
using OtpNet;
using System.Reflection;

namespace CloudSync
{

    public class TwoFactorAuth
    {
        public TwoFactorAuth(SecureStorage.Storage storage)
        {
            Storage = storage;
        }
        SecureStorage.Storage Storage;
        private string _SecretKey;
        private string SecretKey()
        {
            lock (this)
            {
                if (_SecretKey == null)
                    _SecretKey = Storage.Values.Get(nameof(SecretKey), null);
                if (_SecretKey == null)
                {
                    byte[] key = new byte[20];
                    using (var rng = new RNGCryptoServiceProvider())
                    {
                        rng.GetBytes(key);
                    }
                    _SecretKey = Base32Encoding.ToString(key);
                    Storage.Values.Set(nameof(SecretKey), _SecretKey);
                }
                return _SecretKey;
            }
        }

        public void ResetSecretKey()
        {
            lock (this)
            {
                Storage.Values.Delete(nameof(SecretKey), typeof(string));
                _SecretKey = null;
                SecretKey();
            }
        }

        /// <summary>
        /// The string to display as a QR code to set up 2FA
        /// </summary>
        /// <returns>2FA QR Code setting string</returns>
        public string QRCodeUri(string issuer)
        {
            Assembly assembly = Assembly.GetEntryAssembly();
            string appName = assembly.GetName().Name;
            return $"otpauth://totp/{appName}?secret={SecretKey()}&issuer={issuer}";
        }

        public string CurrentTotpCode()
        {
            var totp = new Totp(Base32Encoding.ToBytes(SecretKey()));
            return totp.ComputeTotp();   
        }

        public string ComputeHash(string input)
        {
            using SHA256 sha256 = SHA256.Create();
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
            StringBuilder builder = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                builder.Append(bytes[i].ToString("x2"));
            }
            return builder.ToString();
        }
    }
}
