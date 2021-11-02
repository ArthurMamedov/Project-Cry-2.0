using System;
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
using System.Diagnostics;
using Microsoft.Win32;

namespace Project_Cry_2._0_GUI
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void FunctionalBurronsClickHandler(out string filePath, out string algorithm, out string mode, out string key)
        {
            OpenFileDialog ofd = new OpenFileDialog();
            ofd.ShowDialog();
            filePath = $"\"{ofd.FileName}\"";

            var encryptionAlgorithmComboBox = (ComboBox)FindName("encryptionAlgorithm");
            var encryptionAlgorithmItem = (ComboBoxItem)encryptionAlgorithmComboBox.SelectedItem;
            algorithm = encryptionAlgorithmItem.Content.ToString();

            var encryptionModeComboBox = (ComboBox)FindName("encryptionMode");
            var encryptionModeItem = (ComboBoxItem)encryptionModeComboBox.SelectedItem;
            mode = encryptionModeItem.Content.ToString();

            var passwordBox = (PasswordBox)FindName("passwordBox");
            key = passwordBox.Password.ToString();
        }

        private void buttonEncrypt_Click(object sender, RoutedEventArgs e)
        {
            string filePath;
            string algorithm;
            string mode;
            string key;
            FunctionalBurronsClickHandler(out filePath, out algorithm, out mode, out key);

            Crypt("encrypt", filePath, algorithm, mode, key);
        }

        private void buttonDecrypt_Click(object sender, RoutedEventArgs e)
        {
            string filePath;
            string algorithm;
            string mode;
            string key;
            FunctionalBurronsClickHandler(out filePath, out algorithm, out mode, out key);
            Crypt("decrypt", filePath, algorithm, mode, key);
        }

        private void Crypt(string encryptOrDecrypt, string filePath, string encryptionAlgorithm, string encryptionMode, string encryptionKey)
        {
            try
            {
                using (var process = new Process())
                {
                    process.StartInfo = GetProcessInfo(encryptOrDecrypt, filePath, encryptionAlgorithm, encryptionMode, encryptionKey);
                    process.Start();
                    process.OutputDataReceived += dataReceivedEventHandler;
                    process.BeginOutputReadLine();
                    process.ErrorDataReceived += errorReceivedEventHandler;
                    process.BeginErrorReadLine();
                    process.WaitForExit();
                }
            }
            catch (Exception ex)
            {
                var textBlock = FindName("noWindowsFormsCrutch") as TextBlock;
                textBlock!.Text = ex.Message;
            }
        }

        private ProcessStartInfo GetProcessInfo(string encryptOrDecrypt, string filePath, string encryptionAlgorithm, string encryptionMode, string encryptionKey)
        {
            var processInfo = new ProcessStartInfo();
            processInfo.UseShellExecute = false;
            processInfo.RedirectStandardOutput = true;
            processInfo.FileName = applicationName;
            processInfo.RedirectStandardError = true;
            processInfo.Arguments = $"{encryptOrDecrypt} {filePath} {encryptionAlgorithm} {encryptionMode} {encryptionKey}";
            processInfo.CreateNoWindow = true;
            return processInfo;
        }

        private void dataReceivedEventHandler(object sender, DataReceivedEventArgs args)
        {
            if (args.Data != null)
            {
                MessageBox.Show(args.Data, "Info");
            }
        }

        private void errorReceivedEventHandler(object sender, DataReceivedEventArgs args)
        {
            if (args.Data != null)
            {
                MessageBox.Show(args.Data, "Error");
            }
        }

        private const string applicationName = "Project Cry 2.0.exe";

        private void passwordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            var encryptButton = (Button)FindName("buttonEncrypt");
            var decryptButton = (Button)FindName("buttonDecrypt");
            var passwordBox = (PasswordBox)sender;

            if (passwordBox.Password.Length > 0)
            {
                encryptButton.IsEnabled = true;
                decryptButton.IsEnabled = true;
            }
            else
            {
                encryptButton.IsEnabled = false;
                decryptButton.IsEnabled = false;
            }
        }
    }
}
