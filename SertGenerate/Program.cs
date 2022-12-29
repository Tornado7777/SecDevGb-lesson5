using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SertGenerate
{
    internal class Program
    {
        static void Main(string[] args)
        {
            while(true)
            {
                //Console.Clear();
                Console.WriteLine("~~ Центр генерации сертификатов ~~\n");
                Console.WriteLine("1. Создать коренвой сертификат");
                Console.WriteLine("2. Создать сертификат");
                Console.WriteLine("Выберите подпрограмму (0 - завершение работы приложения):");
                if (int.TryParse(Console.ReadLine(), out int value)) 
                { 
                    switch(value)
                    {
                        case 0:
                            Console.WriteLine("завершение работы приложения.");
                            Console.ReadKey();
                            return;
                        case 1:

                            CertificateConfiguration certificateConfiguration = new CertificateConfiguration
                            {
                                CertName = "Locky Co CA",
                                Email = "test@gmail.com",
                                OutFolder = @"D:\Users\certificate\",
                                Password= "12345678",
                                CertDuration = 30
                            };
                            CertificateGenerationProvider certificateGenerationProvider= new CertificateGenerationProvider();
                            certificateGenerationProvider.GenerateRootCertificate(certificateConfiguration);
                            Console.WriteLine("Корневой сертификат успешно сгенерирован!");
                            break; 
                        case 2:
                            int counter = 0;
                            CertificateExplorerProvider certificateExplorerProvider = new CertificateExplorerProvider(true);
                            certificateExplorerProvider.LoadCertificates();
                            foreach (var certificate in certificateExplorerProvider.Certificates)
                            {
                                Console.WriteLine($"{counter++} >>> {certificate}");
                            }
                            Console.WriteLine("Укажите номер корневого сертификата");

                            if (int.TryParse(Console.ReadLine(), out int certNumber))
                            {
                                CertificateConfiguration addCertificateConfiguration = new CertificateConfiguration
                                {
                                    RootCertificate = certificateExplorerProvider.Certificates[certNumber].Certificate,
                                    CertName = "ITDepartment",
                                    OutFolder = @"D:\Users\certificate\",
                                    Password = "12345678",
                                };
                                CertificateGenerationProvider certificateGenerationProvider2 = new CertificateGenerationProvider();
                                certificateGenerationProvider2.GenerateCertCertificate(addCertificateConfiguration);
                                Console.WriteLine("Сертификат успешно сгенерирован!");
                            }
                            else
                                Console.WriteLine("Сертификата с таким номером не существует.");
                            break;
                        default:
                            Console.WriteLine("Некорректный номер подпрограммы. Пожалуйста повторите ввод.");
                            break;
                    }
                }
                else
                    Console.WriteLine("Некорректный номер подпрограммы. Пожалуйста повторите ввод."); 
            }
        }
    }
}
