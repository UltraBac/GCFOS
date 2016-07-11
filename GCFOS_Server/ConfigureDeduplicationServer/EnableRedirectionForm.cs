using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace ConfigureDeduplicationServer
{
    public partial class EnableRedirectionForm : Form
    {
        String MyName = System.Reflection.Assembly.GetExecutingAssembly().GetName().Name;
        RegistryKey key = null;
        
        public EnableRedirectionForm()
        {
            InitializeComponent();
        }

        private String GetRegStr(RegistryKey key, String Name, String Default = "")
        {
            String Value;
            try
            {
                Value = (String)key.GetValue(Name, Default);
            }
            catch (Exception)
            {
                Value = Default;
            }
            return Value;
        }

        private void EnableRedirectionForm_Load(object sender, EventArgs e)
        {

            try
            {
                key = Registry.LocalMachine.CreateSubKey(my_config.RegistryPath);
                if (key == null)
                    return;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Unable to load key " + my_config.RegistryPath + " : " + ex.Message, MyName,
                    MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                Application.Exit();
            }

            ClientID.Value = (int)key.GetValue(my_config.RegConfigRedirectClientID, 1);
            Secret.Text = GetRegStr(key, my_config.RegConfigRedirectSecret);
            Server.Text = GetRegStr(key, my_config.RegConfigRedirectServer);

        }

        private void Cancel_Click(object sender, EventArgs e)
        {
            if (key != null)
            {
                key.Close();
            }
            Close();
        }

        private bool ValidateSecret()
        {
            if (Secret.Text.Length != 64)
            {
                MessageBox.Show("Secret must be 64 hex characters long", MyName,
                    MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
                return false;
            }
            for (int i = 0; i < 64; i++)
            {
                char c = Secret.Text[i];

                if (c >= '0' && c <= '9')
                    continue;
                if (c >= 'a' && c <= 'f')
                    continue;
                MessageBox.Show("Invalid character in secret -- must be 0-9 or a-f for each character", MyName,
                    MessageBoxButtons.OK, MessageBoxIcon.Asterisk);
                return false;
            }
            return true;
        }

        private void OK_Click(object sender, EventArgs e)
        {
            if (!ValidateSecret())
                return;

            key.SetValue(my_config.RegConfigRedirectSecret, Secret.Text, RegistryValueKind.String);
            key.SetValue(my_config.RegConfigRedirectClientID, ClientID.Value, RegistryValueKind.DWord);
            if (Server.Text.Equals(""))
            {
                key.DeleteValue(my_config.RegConfigRedirectServer, false);
            }
            else
            {
                key.SetValue(my_config.RegConfigRedirectServer, Server.Text, RegistryValueKind.String);
            }
            key.Close();
            MessageBox.Show("Updated registry successfully. Please re-start the service in order for the new values to be used", MyName,
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            Application.Exit(); // end program
        }

    }
}
