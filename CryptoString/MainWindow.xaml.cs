using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
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
using System.Windows.Controls.Primitives;

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

            RandomRadio.IsChecked = true;
            AdvancedOptionsLink_Click(null, null);

            SaltLengthScroller.Minimum = 1;
            SaltLengthScroller.Maximum = 9999;
            SaltLengthScroller.Value = 11;
            SaltLengthScroller.SmallChange = 1;
            SaltLengthScroller.LargeChange = 10;
            SaltLengthScroller.Resources.Add("RelatedTextBox", SaltLengthBox);
            SaltLengthScroller.Resources.Add("DefaultValue", (int)SaltLengthScroller.Value);

            IterationsScroller.Minimum = 1;
            IterationsScroller.Maximum = 2147483647;
            IterationsScroller.Value = 100000;
            IterationsScroller.SmallChange = 10000;
            IterationsScroller.LargeChange = 100000;
            IterationsScroller.Resources.Add("RelatedTextBox", IterationsBox);
            IterationsScroller.Resources.Add("DefaultValue", (int)IterationsScroller.Value);
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                byte[] salt;
                string saltString = "";
                int iterations=0;
                if(!int.TryParse(IterationsBox.Text,out iterations) || iterations < 1)
                {
                    MessageBox.Show("Iterations can't be 0 or empty!", "Wrong iterations format", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                if (RandomRadio.IsChecked == true)
                {
                    if (SaltLengthBox.Text.Length < 1)
                    {
                        throw new ArgumentException();
                    }
                    salt = AES.RandomSalt(int.Parse(SaltLengthBox.Text));
                    saltString = Convert.ToBase64String(salt) + "#";  //# is seperator char
                }
                else if (CustomRadio.IsChecked == true)
                {
                    if (ANSIRadio.IsChecked == true)
                        salt = Encoding.GetEncoding(1252).GetBytes(SaltTextBox.Text);
                    else if (Base64Radio.IsChecked == true)
                        salt = Convert.FromBase64String(SaltTextBox.Text);
                    else
                    {
                        SaltTextBox.Text = SaltTextBox.Text.ToUpper();
                        SaltTextBox.Text = SaltTextBox.Text.Replace(' ', '-');
                        SaltTextBox.Text = SaltTextBox.Text.Replace('-', ':');
                        if (SaltTextBox.Text.Contains(":"))
                        {
                            List<byte> saltList = new List<byte>();
                            foreach (string s in SaltTextBox.Text.Split(':'))
                                saltList.Add(Convert.ToByte(s, 16));

                            salt = saltList.ToArray();
                        }
                        else
                        {
                            salt = BitConverter.GetBytes(Convert.ToInt32(SaltTextBox.Text, 16));
                            if (BitConverter.IsLittleEndian)
                                Array.Reverse(salt);
                        }
                    }
                }
                else
                {
                    ResultBox.Text = AES.EncryptString(InputTextBox.Text, KeyPasswordBox.Password,iterations).Remove(0,5);
                    return;
                }

                ResultBox.Text = saltString + AES.EncryptString(InputTextBox.Text, KeyPasswordBox.Password, ref salt,iterations).Remove(0,5);
            }
            catch (ArgumentNullException)
            {
                MessageBox.Show("Please enter a text and a password!", "Nothing entered", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch(ArgumentException)
            {
                MessageBox.Show("Salt must be at least 8 bytes (8 characters) long!", "Salt too small", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch(FormatException)
            {
                MessageBox.Show("If you check Base64 then the salt must be in Base64 format!", "No Base64 format", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception)
            {
                MessageBox.Show("An unexpected error occured!", "Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }
        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            try     //+4917639275150
            {
                /*string[] input = InputTextBox.Text.Split('#');
                byte[] salt = Encoding.ASCII.GetBytes(input[0]);
                ResultBox.Text = AES.DecryptString(input[1], KeyPasswordBox.Password,ref salt);*/
                string[] input = { InputTextBox.Text };
                byte[] salt;
                int iterations = 0;
                if (!int.TryParse(IterationsBox.Text, out iterations) || iterations < 1)
                {
                    MessageBox.Show("Iterations can't be 0 or empty!", "Wrong iterations format", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }

                if (RandomRadio.IsChecked == true)
                {
                    input = InputTextBox.Text.Split('#');
                    salt = Convert.FromBase64String(input[0]);
                    input[0] = input[1];
                }
                else if (CustomRadio.IsChecked == true)
                {
                    if (ANSIRadio.IsChecked == true)
                        salt = Encoding.GetEncoding(1252).GetBytes(SaltTextBox.Text);
                    else if (Base64Radio.IsChecked == true)
                        salt = Convert.FromBase64String(SaltTextBox.Text);
                    else
                    {
                        SaltTextBox.Text = SaltTextBox.Text.ToUpper();
                        SaltTextBox.Text = SaltTextBox.Text.Replace(' ', '-');
                        SaltTextBox.Text = SaltTextBox.Text.Replace('-', ':');
                        if (SaltTextBox.Text.Contains(":"))
                        {
                            List<byte> saltList = new List<byte>();
                            foreach (string s in SaltTextBox.Text.Split(':'))
                                saltList.Add(Convert.ToByte(s, 16));

                            salt = saltList.ToArray();
                        }
                        else
                        {
                            salt = BitConverter.GetBytes(Convert.ToInt32(SaltTextBox.Text, 16));
                            if (BitConverter.IsLittleEndian)
                                Array.Reverse(salt);
                        }
                    }
                }
                else
                {
                    ResultBox.Text = AES.DecryptString("EAAAA" + InputTextBox.Text, KeyPasswordBox.Password,iterations);
                    return;
                }

                ResultBox.Text = AES.DecryptString("EAAAA" + input[0], KeyPasswordBox.Password, ref salt,iterations);
            }
            catch (ArgumentNullException)
            {
                MessageBox.Show("Please enter a text and a password!", "Nothing entered", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (ArgumentException)
            {
                MessageBox.Show("Salt must be at least 8 bytes (8 characters) long!", "Salt too small", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (System.Security.Cryptography.CryptographicException)
            {
                MessageBox.Show("Wrong password, salt or number of iterations!", "Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (FormatException)
            {
                MessageBox.Show("Invalid encrypted text!", "Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch(IndexOutOfRangeException)
            {
                MessageBox.Show("Invalid encrypted text!", "Failed", MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
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
                Height = 555;
                SaltEncodingRadioButtons.Visibility = Visibility.Visible;
                SaltRadioButtons.Visibility = Visibility.Visible;
                SaltLengthBox.Visibility = SaltLengthScroller.Visibility = SaltLengthBlock.Visibility = Visibility.Visible;
                IterationsBox.Visibility = IterationsScroller.Visibility = IterationsLabel.Visibility = Visibility.Visible;
                SaltPlaceholder.Visibility = SaltTextBox.Visibility = Visibility.Visible;
            }
            else if (AdvanedOptionsLinkText.Text[0] == '▼') //Advanced options menu is pulled down
            {
                AdvanedOptionsLinkText.Text = AdvanedOptionsLinkText.Text.Replace('▼', '▶');
                Height = 375;
                SaltEncodingRadioButtons.Visibility = Visibility.Hidden;
                SaltRadioButtons.Visibility = Visibility.Hidden;
                SaltLengthBox.Visibility = SaltLengthScroller.Visibility = SaltLengthBlock.Visibility = Visibility.Hidden;
                IterationsBox.Visibility = IterationsScroller.Visibility = IterationsLabel.Visibility = Visibility.Hidden;
                SaltPlaceholder.Visibility = SaltTextBox.Visibility = Visibility.Hidden;
            }
        }

        private void SaltTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (SaltTextBox.Text == "" || SaltTextBox.Text == null)
                SaltPlaceholder.Visibility = Visibility.Visible;
            else
                SaltPlaceholder.Visibility = Visibility.Hidden;
        }

        private void RandomRadio_Checked(object sender, RoutedEventArgs e)
        {
            SaltLengthBox.IsEnabled = SaltLengthScroller.IsEnabled = true;
        }
        private void RandomRadio_Unchecked(object sender, RoutedEventArgs e)
        {
            SaltLengthBox.IsEnabled = SaltLengthScroller.IsEnabled = false;
        }

        private void CustomRadio_Checked(object sender, RoutedEventArgs e)
        {
            SaltEncodingRadioButtons.IsEnabled = true;
            SaltTextBox.IsEnabled = true;
            //SaltTextBox.Background = new SolidColorBrush(Color.FromScRgb(0x00,0xFF, 0xFF, 0xFF));
        }
        private void CustomRadio_Unchecked(object sender, RoutedEventArgs e)
        {
            SaltEncodingRadioButtons.IsEnabled = false;
            SaltTextBox.IsEnabled = false;
            //SaltTextBox.Background = new SolidColorBrush(Color.FromScRgb(0x3F, 0xA6, 0xA6, 0xA6));
        }

        private void NumberBox_PreviewTextInput(object sender, TextCompositionEventArgs e)
        {
            TextBox numberBox = (TextBox)sender;
            try { if(uint.Parse(numberBox.Text.Insert(numberBox.CaretIndex,e.Text))>int.MaxValue) throw new OverflowException(); }
            catch(OverflowException)
            {
                e.Handled = true;
                MessageBox.Show("Due to integer overflow value can't be bigger than " + int.MaxValue, "Overflow", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }
            catch { }
            e.Handled = !IsTextAllowed(e.Text);
        }
        private void NumberBox_Pasting(object sender, DataObjectPastingEventArgs e)
        {if (e.DataObject.GetDataPresent(typeof(String)))
            {
                String text = (String)e.DataObject.GetData(typeof(String));
                TextBox numberBox = (TextBox)sender;

                try { if (uint.Parse(numberBox.Text.Insert(numberBox.CaretIndex, text)) > int.MaxValue) throw new OverflowException(); }
                catch (OverflowException)
                {
                    e.Handled = true;
                    MessageBox.Show("Due to integer overflow value can't be bigger than " + int.MaxValue, "Overflow", MessageBoxButton.OK, MessageBoxImage.Information);
                    return;
                }
                catch { }

                if (!IsTextAllowed(text))
                {
                    e.CancelCommand();
                }
            }
            else
            {
                e.CancelCommand();
            }
        }
        private static bool IsTextAllowed(string text)
        {
            string allowedText = "0123456789";
            for (int i = 0; i < allowedText.Length; i++)
                for (int j = 0; j < text.Length; j++)
                    if (!allowedText.Contains(text[j]))
                        return false;

            return true;
        }

        /*private void ScrollBar_Scroll(object sender, ScrollEventArgs e)
        {
            ScrollBar sb = (ScrollBar)sender;

            int oldValue = int.Parse(SaltLengthBox.Text);
            int delta = (oldValue - (int)sb.Value);     //Invert direction

            if (e.ScrollEventType == ScrollEventType.First)
                sb.Value = 9999;
            else if (e.ScrollEventType == ScrollEventType.Last)
                sb.Value = 1;
            else
                sb.Value = oldValue + delta;

            SaltLengthBox.Text = sb.Value.ToString();
        }*/
        
        private void NumberBox_Scroll(object sender, ScrollEventArgs e)
        {
            ScrollBar sb = (ScrollBar)sender;
            TextBox tb = (TextBox)sb.FindResource("RelatedTextBox");

            int defaultValue = (int)sb.FindResource("DefaultValue");
            long oldValue = long.Parse(tb.Text);
            int delta = (defaultValue - (int)sb.Value);     //Invert direction
            sb.Value = defaultValue;

            if (e.ScrollEventType == ScrollEventType.First || oldValue + delta > sb.Maximum)
                tb.Text = sb.Maximum.ToString();
            else if (e.ScrollEventType == ScrollEventType.Last || oldValue + delta < sb.Minimum)
                tb.Text = sb.Minimum.ToString();
            else
                tb.Text = (oldValue + delta).ToString();
        }
    }
}