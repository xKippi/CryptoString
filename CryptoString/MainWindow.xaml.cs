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

namespace CryptoString
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

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                byte[] salt = AES.RandomASCIISalt(10, '#');
                ResultBox.Text = Encoding.ASCII.GetString(salt) + "#" + AES.EncryptString(InputTextBox.Text, KeyPasswordBox.Password, ref salt);
            }
            catch (ArgumentNullException)
            {
                MessageBox.Show("Please enter a text and a password!", "Nothing entered", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception)
            {
                MessageBox.Show("An unexpected error occured!", "Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                string[] input = InputTextBox.Text.Split('#');
                byte[] salt = Encoding.ASCII.GetBytes(input[0]);
                ResultBox.Text = AES.DecryptString(input[1], KeyPasswordBox.Password,ref salt);
            }
            catch (ArgumentNullException)
            {
                MessageBox.Show("Please enter a text and a password!", "Nothing entered", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                MessageBox.Show("Wrong Password!", "Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (System.FormatException)
            {
                MessageBox.Show("Invalid encrypted text!", "Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception)
            {
                MessageBox.Show("An unexpected error occured!", "Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void InputTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (InputTextBox.Text == "" || InputTextBox.Text == null)
                InputPlaceholder.Visibility = Visibility.Visible;
            else
                InputPlaceholder.Visibility = Visibility.Hidden;
        }

        private void KeyPasswordBox_PasswordChanged(object sender, RoutedEventArgs e)
        {
            if (KeyPasswordBox.Password == "" || KeyPasswordBox.Password == null)
                PasswordPlaceholder.Visibility = Visibility.Visible;
            else
                PasswordPlaceholder.Visibility = Visibility.Hidden;
        }

        private void AdvancedOptionsLink_Click(object sender, RoutedEventArgs e)
        {
            if (AdvanedOptionsLinkText.Text[0] == '▶') //Advanced options menu is not pulled down
            {
                AdvanedOptionsLinkText.Text = AdvanedOptionsLinkText.Text.Replace('▶', '▼');


            }
            else if (AdvanedOptionsLinkText.Text[0] == '▼') //Advanced options menu is pulled down
            {
                AdvanedOptionsLinkText.Text = AdvanedOptionsLinkText.Text.Replace('▼', '▶');

            }
        }

        /*private void SaltTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {

            if (SaltTextBox.Text == "" || SaltTextBox.Text == null)
                SaltPlaceholder.Visibility = Visibility.Visible;
            else
                SaltPlaceholder.Visibility = Visibility.Hidden;
        }*/
    }
}