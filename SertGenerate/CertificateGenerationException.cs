using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SertGenerate
{
    internal class CertificateGenerationException : Exception
    {
        public CertificateGenerationException(string message) : base (message) { }
    }
}
