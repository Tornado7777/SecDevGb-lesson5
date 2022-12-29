using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using System.Collections;
using System.Reflection;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1;

namespace SertGenerate
{
    internal class CertificateGenerationProvider
    {
        public void GenerateRootCertificate(CertificateConfiguration settings)
        {
            SecureRandom secRand = new SecureRandom();
            RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();
            RsaKeyGenerationParameters prms = new RsaKeyGenerationParameters(new Org.BouncyCastle.Math.BigInteger("10001", 16),
                secRand, 1024, 25);
            keyGen.Init(prms);
            AsymmetricCipherKeyPair keyPair= keyGen.GenerateKeyPair();

            string issure = "CN=" + settings.CertName;

            // определим имена файлов
            string p12FileName = settings.OutFolder + @"\" + settings.CertName + ".p12";
            string crtFileName = settings.OutFolder + @"\" + settings.CertName + ".crt";

            //Серийный номер сертификата
            byte[] serialNumber = Guid.NewGuid().ToByteArray();
            serialNumber[0] = (byte)(serialNumber[0] & 0x7f);

            X509V3CertificateGenerator certGen= new X509V3CertificateGenerator();
            certGen.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(1, serialNumber));
            certGen.SetIssuerDN(new X509Name(issure));
            certGen.SetNotBefore(DateTime.Now.ToUniversalTime());
            certGen.SetNotAfter(DateTime.Now.ToUniversalTime() + new TimeSpan(settings.CertDuration * 365, 0, 0, 0));
            certGen.SetSubjectDN(new X509Name(issure));
            certGen.SetPublicKey(keyPair.Public);
            certGen.SetSignatureAlgorithm("MD5WITHRSA");
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(keyPair.Public));
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(keyPair.Public));
            certGen.AddExtension(X509Extensions.BasicConstraints, false,
                new BasicConstraints(true));

            Org.BouncyCastle.X509.X509Certificate rootCert = certGen.Generate(keyPair.Private);

            //Получим подписанный сертификат
            byte[] rawCert = rootCert.GetEncoded();

            //созраним закрытую часть сертификата
            try
            {
                using (FileStream fs = new FileStream(p12FileName, FileMode.Create))
                {
                    Pkcs12Store p12 = new Pkcs12Store();
                    X509CertificateEntry certEntry = new X509CertificateEntry(rootCert);
                    p12.SetKeyEntry(settings.CertName, new AsymmetricKeyEntry(keyPair.Private),
                        new X509CertificateEntry[] { certEntry });
                    p12.Save(fs, settings.Password.ToCharArray(), secRand);
                    fs.Close();
                }
            }
            catch (Exception ex)
            {
                throw new CertificateGenerationException("При сохранении закрытой части сертификата произошла ошибкаю\r\n" +
                    ex.Message);
            }

            //сохраним открытую часть сертификат
            try
            {
                using (FileStream fs = new FileStream(crtFileName, FileMode.Create))
                {
                    fs.Write(rawCert, 0, rawCert.Length);
                    fs.Close();
                }
            }
            catch (Exception ex)
            {
                throw new CertificateGenerationException("При сохранении открытой части сертификата произошла ошибкаю\r\n" +
                    ex.Message);
            }
        }

        public void GenerateCertCertificate(CertificateConfiguration settings)
        {
            //Получим совместимый с ВС корневой сертификат
            Org.BouncyCastle.X509.X509Certificate rootCertificateInternational =
                DotNetUtilities.FromX509Certificate(settings.RootCertificate);

            //генерация пары ключей
            SecureRandom secRand = new SecureRandom();
            RsaKeyPairGenerator keyGen = new RsaKeyPairGenerator();
            RsaKeyGenerationParameters prms = new RsaKeyGenerationParameters(new Org.BouncyCastle.Math.BigInteger("10001", 16),
                secRand, 1024, 25);
            keyGen.Init(prms);
            AsymmetricCipherKeyPair keyPair = keyGen.GenerateKeyPair();

            string subject = "CN=" + settings.CertName;

            // определим имена файлов
            string p12FileName = settings.OutFolder + @"\" + settings.CertName + ".p12";
            //string crtFileName = settings.OutFolder + @"\" + settings.CertName + ".crt";

            //Серийный номер сертификата
            byte[] serialNumber = Guid.NewGuid().ToByteArray();
            serialNumber[0] = (byte)(serialNumber[0] & 0x7f);

            X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
            certGen.SetSerialNumber(new Org.BouncyCastle.Math.BigInteger(1, serialNumber));
            certGen.SetIssuerDN(rootCertificateInternational.IssuerDN);
            certGen.SetNotBefore(DateTime.Now.ToUniversalTime());
            certGen.SetNotAfter(DateTime.Now.AddDays(100));
            certGen.SetSubjectDN(new X509Name(subject));
            certGen.SetPublicKey(keyPair.Public);
            certGen.SetSignatureAlgorithm("MD5WITHRSA");
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false,
                new AuthorityKeyIdentifierStructure(rootCertificateInternational.GetPublicKey()));
            certGen.AddExtension(X509Extensions.SubjectKeyIdentifier, false,
                new SubjectKeyIdentifierStructure(keyPair.Public));
            KeyUsage keyUsage = new KeyUsage(settings.CertName.EndsWith("CA") ? 182 : 176);
            certGen.AddExtension(X509Extensions.KeyUsage, true, keyUsage);
            ArrayList keyPurposes = new ArrayList();
            keyPurposes.Add(KeyPurposeID.IdKPServerAuth);
            keyPurposes.Add(KeyPurposeID.IdKPCodeSigning);
            keyPurposes.Add(KeyPurposeID.IdKPEmailProtection);
            keyPurposes.Add(KeyPurposeID.IdKPClientAuth);
            certGen.AddExtension(X509Extensions.ExtendedKeyUsage, true,
                new ExtendedKeyUsage(keyPurposes));
            
            if (settings.CertName.EndsWith("CA"))
            {
                certGen.AddExtension(X509Extensions.BasicConstraints, false,
                    new BasicConstraints(true));
            }

            //теперь нужно достать готовый к подписанию сертификат
            FieldInfo fi = typeof(X509V3CertificateGenerator).GetField("tbsGen", BindingFlags.NonPublic| BindingFlags.Instance);
            V3TbsCertificateGenerator v3TbsCertificateGenerator = (V3TbsCertificateGenerator)fi.GetValue(certGen);
            TbsCertificateStructure tbsCert = v3TbsCertificateGenerator.GenerateTbsCertificate();

            //Расчет MD5-хэш тела сертификата
            MD5 md5 = new MD5CryptoServiceProvider();
            byte[] tbsCertHash = md5.ComputeHash(tbsCert.GetDerEncoded());
            //Подписать сертификат штатными средствами .Net,
            // т.к. они используют Crypto API, закрытый ключ  Майкрософт не даст
            RSAPKCS1SignatureFormatter signer = new RSAPKCS1SignatureFormatter();
            signer.SetHashAlgorithm("MD5");
            signer.SetKey(settings.RootCertificate.PrivateKey);

            byte[] certSignature = signer.CreateSignature(tbsCertHash);
            //теперь можем сформировать сертификат с подписью



            Org.BouncyCastle.X509.X509Certificate signedCertificate = new Org.BouncyCastle.X509.X509Certificate(
                new X509CertificateStructure(tbsCert,
                new AlgorithmIdentifier(PkcsObjectIdentifiers.MD5WithRsaEncryption),
                new DerBitString(certSignature)));

            //Получим подписанный сертификат
            //byte[] rawCert = rootCert.GetEncoded();

            //созраним закрытую часть сертификата
            //формируем стандартное хранилище .p12 для сертификат
            try
            {
                using (FileStream fs = new FileStream(p12FileName, FileMode.Create))
                {
                    Pkcs12Store p12 = new Pkcs12Store();
                    X509CertificateEntry certEntry = new X509CertificateEntry(signedCertificate);
                    X509CertificateEntry rootCertEntry = new X509CertificateEntry(rootCertificateInternational);
                    p12.SetKeyEntry(settings.CertName, new AsymmetricKeyEntry(keyPair.Private),
                        new X509CertificateEntry[] { certEntry , rootCertEntry });
                    p12.Save(fs, settings.Password.ToCharArray(), secRand);
                    fs.Close();
                }
            }
            catch (Exception ex)
            {
                throw new CertificateGenerationException("При сохранении закрытой части сертификата произошла ошибкаю\r\n" +
                    ex.Message);
            }
            
        }

    }
}
