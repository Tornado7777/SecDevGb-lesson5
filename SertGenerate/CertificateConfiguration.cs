using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SertGenerate
{
    public class CertificateConfiguration
    {
        public X509Certificate2 RootCertificate { get; set; }

        //длительность жизни сертификата
        public int CertDuration { get; set; }
        public string CertName { get; set; }
        public string Password { get; set; }
        //public string PasswordConfirm { get; set; }
        public string OutFolder { get; set; }
        //public string SaveInStore { get; set; }
        public string Email { get; set; }
    }
}
