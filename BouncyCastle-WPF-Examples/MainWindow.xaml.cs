using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Generators;
using System.Security.Cryptography.X509Certificates;

namespace BouncyCastle_WPF_Examples
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var keyGenerate = new RsaKeyPairGenerator();
            keyGenerate.Init(new KeyGenerationParameters(new SecureRandom(new CryptoApiRandomGenerator()), 1024));

            AsymmetricCipherKeyPair asymmetricCipherKeyPair = keyGenerate.GenerateKeyPair();

            var generate = new X509V3CertificateGenerator();

            var certName = new X509Name("CN=CA");
            var serialNo = new BigInteger("1", 10);

            generate.SetSerialNumber(serialNo);
            generate.SetSubjectDN(certName);
            generate.SetIssuerDN(certName);
            generate.SetNotAfter(DateTime.Now.AddYears(100));
            generate.SetNotBefore(DateTime.Now);
            generate.SetSignatureAlgorithm("SHA1WITHRSA");
            generate.SetPublicKey(asymmetricCipherKeyPair.Public);

            var myCert = generate.Generate(asymmetricCipherKeyPair.Private);
            byte[] result = DotNetUtilities.ToX509Certificate(myCert).Export(X509ContentType.Cert);

            textResult.Text += "Certificate generated! Writing to FS.\n";

            if (File.Exists(Directory.GetCurrentDirectory() + "\\test.crt"))
            {
                textResult.Text += "Certificate file already present. Stopping.";
                return;
            }

            FileStream fileStream = new FileStream(String.Format(Directory.GetCurrentDirectory() + "\\test.crt"), FileMode.CreateNew);
            fileStream.Write(result, 0, result.Length);
            textResult.Text += String.Format($"Certificate is located at: {Directory.GetCurrentDirectory() + "\\test.crt"}");
            fileStream.Flush();
            fileStream.Close();
        }
    }
}
