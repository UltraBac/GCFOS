/*
This file forms part of the GCFOS project

Copyright(C) 2014-2016 UltraBac Software, Paul Bunn

This program is free software : you can redistribute it and / or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.If not, see <http://www.gnu.org/licenses/>.


This software was developed by Paul Bunn (paul.bunn <at> icloud.com)
Commercial licenses are availble from UltraBac, please contact
sales@ultrabac.com


*/

using System;
using System.IO;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;
using System.Configuration;
using Amazon.S3;
using Amazon.S3.Model;
using net.openstack;
using net.openstack.Core.Domain;
using net.openstack.Core.Providers;
using net.openstack.Providers.Rackspace;
using net.openstack.Providers.Hp;
using net.openstack.Core.Exceptions.Response;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Auth;
using Microsoft.WindowsAzure.Storage.Blob;

namespace ConfigureDeduplicationServer
{
    public partial class MainForm : Form
    {
        ToolTip tt_Location;
        ToolTip tt_Secondary_Location;
        ToolTip tt_General_Cloud;
        ToolTip tt_AccessKey_OpenStack;
        ToolTip tt_Region;
        String MyName = System.Reflection.Assembly.GetExecutingAssembly().GetName().Name;

        public MainForm()
        {
            InitializeComponent();
        }

        public bool ValidateLocalPath(String path)
        {
            if (path.Equals(""))
                return true; // no path specified

            if (path.Length < 4)
            {
                MessageBox.Show("'" + path + "' - invalid", MyName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return false;
            }

            try
            {
                DirectoryInfo dirinfo = new DirectoryInfo(path);
                if (dirinfo.Exists)
                    return true;

                if (!dirinfo.FullName.Equals(path, StringComparison.InvariantCultureIgnoreCase))
                {
                    MessageBox.Show("'" + path + "' - please use fully qualified path", MyName, MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return false;
                }

                if (MessageBox.Show("'" + path + "' does not exist or is invalid, would you like to try to create it?", MyName,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.No)
                {
                    return false;
                }
                dirinfo.Create(); // create the directory
                return true;
            }
            catch (Exception e)
            {
                MessageBox.Show("Failed to validate '" + path + "' : " + e.Message, MyName, MessageBoxButtons.OK, MessageBoxIcon.Error);
                return false;
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            List<string> _items = new List<string>();
            _items.Add(my_config.RepositoryTypeDisplayNone);
            _items.Add(my_config.RepositoryTypeDisplayPath);
            _items.Add(my_config.RepositoryTypeDisplayS3);
            _items.Add(my_config.RepositoryTypeDisplayAzure);
            _items.Add(my_config.RepositoryTypeDisplayOpenStack);
            PrimaryRepositoryType.DataSource = _items;
            SecondaryRepositoryType.DataSource = new List<string>(_items);

            ToolTip tt1 = new ToolTip();
            tt1.SetToolTip(this.DBInitialSize, my_config.DBInitialSize_tt);

            ToolTip tt2 = new ToolTip();
            tt2.SetToolTip(this.DBGrowthSize, my_config.DBGrowthSize_tt);

            ToolTip tt3 = new ToolTip();
            tt3.SetToolTip(this.RetentionDays, my_config.RetentionDays_tt);

            ToolTip tt4 = new ToolTip();
            tt4.SetToolTip(this.FileResidencyThreshold, my_config.ResidencyThreshold_tt);

            ToolTip tt5 = new ToolTip();
            tt5.SetToolTip(this.AdvertiseService, my_config.AdvertiseService_tt);

            ToolTip tt6 = new ToolTip();
            tt6.SetToolTip(this.BlockStoreLocation, my_config.BlockStoreLocation_tt);

            ToolTip tt7 = new ToolTip();
            tt7.SetToolTip(this.LocalLCUDLocation, my_config.LCUD_Location_tt);

            ToolTip tt8 = new ToolTip();
            tt8.SetToolTip(this.RepositoryLCUDLocation, my_config.Repository_LCUD_Location_tt);

            // these following tool tips are dynamically assigned based on field choices
            tt_Location = new ToolTip();
            tt_Secondary_Location = new ToolTip();

            tt_Region = new ToolTip();

            tt_General_Cloud = new ToolTip();
            tt_General_Cloud.SetToolTip(this.RepositoryEndpoint, my_config.General_Cloud_Provider_tt);
            tt_General_Cloud.SetToolTip(this.RepositorySecretKey, my_config.General_Cloud_Provider_tt);
            tt_General_Cloud.SetToolTip(this.SecondaryRepositoryEndpoint, my_config.General_Cloud_Provider_tt);
            tt_General_Cloud.SetToolTip(this.SecondaryRepositoryRegion, my_config.General_Cloud_Provider_tt);
            tt_General_Cloud.SetToolTip(this.SecondaryRepositorySecretKey, my_config.General_Cloud_Provider_tt);

            tt_AccessKey_OpenStack = new ToolTip();

            LoadValuesFromRegistry();
        }

        private void PrimaryRepositoryType_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayAzure, StringComparison.CurrentCultureIgnoreCase))
            {
                tt_Location.SetToolTip(this.RepositoryLocation, my_config.Location_Azure_tt);
                tt_Region.SetToolTip(this.RepositoryRegion, null);
                tt_AccessKey_OpenStack.SetToolTip(this.RepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.RepositoryAccessKey, my_config.General_Cloud_Provider_tt);
                tt_General_Cloud.SetToolTip(this.RepositoryRegion, null);
                tt_General_Cloud.SetToolTip(this.RepositoryLocation, null);
            }
            else if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayS3, StringComparison.CurrentCultureIgnoreCase))
            {
                tt_Location.SetToolTip(this.RepositoryLocation, my_config.Location_S3_tt);
                tt_Region.SetToolTip(this.RepositoryRegion, my_config.Region_S3_tt);
                tt_AccessKey_OpenStack.SetToolTip(this.RepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.RepositoryAccessKey, my_config.General_Cloud_Provider_tt);
                tt_General_Cloud.SetToolTip(this.RepositoryRegion, null);
                tt_General_Cloud.SetToolTip(this.RepositoryLocation, null);

                if (RepositoryEndpoint.Text.Length == 0)
                {
                    RepositoryEndpoint.Text = @"https://s3.amazonaws.com";
                }
            }
            else if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayPath, StringComparison.CurrentCultureIgnoreCase))
            {
                tt_Region.SetToolTip(this.RepositoryRegion, null);
                tt_Location.SetToolTip(this.RepositoryLocation, my_config.Location_Path_tt);
                tt_AccessKey_OpenStack.SetToolTip(this.RepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.RepositoryAccessKey, my_config.General_Cloud_Provider_tt);
                tt_General_Cloud.SetToolTip(this.RepositoryRegion, my_config.General_Cloud_Provider_tt);

                if (RepositoryLocation.Text.IndexOf("HTTP", StringComparison.CurrentCultureIgnoreCase) == 0)
                {
                    RepositoryLocation.Text = "";
                }
            }
            else if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayNone, StringComparison.CurrentCultureIgnoreCase))
            {
                tt_Region.SetToolTip(this.RepositoryRegion, null);
                tt_Location.SetToolTip(this.RepositoryLocation, null);
                tt_AccessKey_OpenStack.SetToolTip(this.RepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.RepositoryAccessKey, my_config.General_Cloud_Provider_tt);
                tt_General_Cloud.SetToolTip(this.RepositoryRegion, my_config.General_Cloud_Provider_tt);
            }
            else if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayOpenStack, StringComparison.CurrentCultureIgnoreCase))
            {
                tt_Region.SetToolTip(this.RepositoryRegion, null);
                tt_Location.SetToolTip(this.RepositoryLocation, my_config.Location_OpenStack_tt);
                tt_AccessKey_OpenStack.SetToolTip(this.RepositoryAccessKey, my_config.AccessKey_OpenStack_tt);
                tt_General_Cloud.SetToolTip(this.RepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.RepositoryRegion, my_config.General_Cloud_Provider_tt);
            }

            ValidateForm();
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

        private Int32 GetRegNum(RegistryKey key, String Name, Int32 Default = 0)
        {
            Int32 Value;
            try
            {
                Value = (Int32)key.GetValue(Name, Default);
            }
            catch (Exception)
            {
                Value = Default;
            }
            return Value;
        }

        private void EnsureWithinRange(NumericUpDown setting, Decimal value)
        {
            if(value > setting.Maximum)
                value = setting.Maximum;
            if(value < setting.Minimum)
                value = setting.Minimum;
            setting.Value = value;
            return;
        }

        private void LoadValuesFromRegistry()
        {
            int value;
            String str;
            RegistryKey key = null;

            try
            {
                key = Registry.LocalMachine.CreateSubKey(my_config.RegistryPath);
                if (key == null)
                    return;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Unable to load key " + my_config.RegistryPath + " : "+ ex.Message, MyName,
                    MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                Application.Exit();
            }
            EnsureWithinRange(FileResidencyThreshold, GetRegNum(key, my_config.RegResidencyThreshold, 4));
            EnsureWithinRange(RetentionDays, GetRegNum(key, my_config.RegRetentionDays, 30));

            str = GetRegStr(key, my_config.RegRepositoryType);
            str = (String)key.GetValue(my_config.RegRepositoryType, my_config.RegRepositoryTypePath);
            if (str.Equals(my_config.RegRepositoryTypePath, StringComparison.CurrentCultureIgnoreCase))
            {
                PrimaryRepositoryType.SelectedIndex = PrimaryRepositoryType.FindString(my_config.RepositoryTypeDisplayPath);
            }
            else if (str.Equals(my_config.RegRepositoryTypeS3, StringComparison.CurrentCultureIgnoreCase))
            {
                PrimaryRepositoryType.SelectedIndex = PrimaryRepositoryType.FindString(my_config.RepositoryTypeDisplayS3);
            }
            else if (str.Equals(my_config.RegRepositoryTypeOpenStack, StringComparison.CurrentCultureIgnoreCase))
            {
                PrimaryRepositoryType.SelectedIndex = PrimaryRepositoryType.FindString(my_config.RepositoryTypeDisplayOpenStack);
            }
            else if (str.Equals(my_config.RegRepositoryTypeAzure, StringComparison.CurrentCultureIgnoreCase))
            {
                PrimaryRepositoryType.SelectedIndex = PrimaryRepositoryType.FindString(my_config.RepositoryTypeDisplayAzure);
            }
            else
            {
                PrimaryRepositoryType.SelectedIndex = PrimaryRepositoryType.FindString(my_config.RepositoryTypeDisplayNone);
            }
            RepositoryLocation.Text = GetRegStr(key, my_config.RegRepositoryLocation);

            RepositoryRegion.Text = GetRegStr(key, my_config.RegRepositoryRegion);
            RepositoryEndpoint.Text = GetRegStr(key, my_config.RegRepositoryEndpoint);
            RepositoryAccessKey.Text = GetRegStr(key, my_config.RegRepositoryAccessKey);
            RepositorySecretKey.Text = GetRegStr(key, my_config.RegRepositorySecretKey);
            BlockStoreLocation.Text = GetRegStr(key, my_config.RegBlockStoreLocation);
            RepositoryLCUDLocation.Text = GetRegStr(key, my_config.RegRepositoryLCUDLocation);
            LocalLCUDLocation.Text = GetRegStr(key, my_config.RegLocalLCUDLocation);

            str = GetRegStr(key, my_config.RegSecondaryRepositoryType);
            SecondaryRepositoryType.SelectedIndex = 0;
            if (str.Equals(my_config.RegRepositoryTypePath, StringComparison.CurrentCultureIgnoreCase))
            {
                SecondaryRepositoryType.SelectedIndex = SecondaryRepositoryType.FindString(my_config.RepositoryTypeDisplayPath);
            }
            else if (str.Equals(my_config.RegRepositoryTypeS3, StringComparison.CurrentCultureIgnoreCase))
            {
                SecondaryRepositoryType.SelectedIndex = SecondaryRepositoryType.FindString(my_config.RepositoryTypeDisplayS3);
            }
            else if (str.Equals(my_config.RegRepositoryTypeOpenStack, StringComparison.CurrentCultureIgnoreCase))
            {
                SecondaryRepositoryType.SelectedIndex = SecondaryRepositoryType.FindString(my_config.RepositoryTypeDisplayOpenStack);
            }
            else if (str.Equals(my_config.RegRepositoryTypeAzure, StringComparison.CurrentCultureIgnoreCase))
            {
                SecondaryRepositoryType.SelectedIndex = SecondaryRepositoryType.FindString(my_config.RepositoryTypeDisplayAzure);
            }
            else
            {
                SecondaryRepositoryType.SelectedIndex = SecondaryRepositoryType.FindString(my_config.RepositoryTypeDisplayNone);
            }
            SecondaryRepositoryLocation.Text = GetRegStr(key, my_config.RegSecondaryRepositoryLocation);
            SecondaryRepositoryRegion.Text = GetRegStr(key, my_config.RegSecondaryRepositoryRegion);
            SecondaryRepositoryEndpoint.Text = GetRegStr(key, my_config.RegSecondaryRepositoryEndpoint);
            SecondaryRepositoryAccessKey.Text = GetRegStr(key, my_config.RegSecondaryRepositoryEndpoint);
            SecondaryRepositoryAccessKey.Text = GetRegStr(key, my_config.RegSecondaryRepositoryAccessKey);
            SecondaryRepositorySecretKey.Text = GetRegStr(key, my_config.RegSecondaryRepositorySecretKey);
            SecondaryBlockStoreLocation.Text = GetRegStr(key, my_config.RegSecondaryBlockStoreLocation);

            // Read database parameters
            DBInitialSize.Value = GetRegNum(key, my_config.RegDBInitialSize, (int)16384);
            DBGrowthSize.Value = GetRegNum(key, my_config.RegDBGrowthSize, (int)1024);

            value = GetRegNum(key, my_config.RegAdvertiseService, (int)1);
            AdvertiseService.Checked = (value > 0);

            key.Close();

            ValidateForm();
        }

        private bool ValidateForm()
        {
            if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayPath, StringComparison.CurrentCultureIgnoreCase))
            {
                RepositoryLocationPicker.Visible = true;
                LCUD_Picker.Visible = true;
                RepositoryRegion.Enabled = false;
                RepositoryEndpoint.Enabled = false;
                RepositoryAccessKey.Enabled = false;
                RepositorySecretKey.Enabled = false;
                RepositoryLocation.Enabled = true;
                RepositoryLCUDLocation.Enabled = false;
                LocalLCUDLocation.Enabled = true;
            }
            else if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayNone, StringComparison.CurrentCultureIgnoreCase))
            {
                RepositoryLocationPicker.Visible = false;
                LCUD_Picker.Visible = false;
                RepositoryRegion.Enabled = false;
                RepositoryEndpoint.Enabled = false;
                RepositoryAccessKey.Enabled = false;
                RepositorySecretKey.Enabled = false;
                RepositoryLocation.Enabled = false;
                RepositoryLCUDLocation.Enabled = false;
                LocalLCUDLocation.Enabled = false;
            }
            else
            {
                RepositoryLocationPicker.Visible = false;
                LCUD_Picker.Visible = false;
                RepositoryRegion.Enabled = true;
                RepositoryEndpoint.Enabled = true;
                RepositoryAccessKey.Enabled = true;
                RepositorySecretKey.Enabled = true;
                RepositoryLocation.Enabled = true;
                LocalLCUDLocation.Enabled = true;
                RepositoryLCUDLocation.Enabled = true;
                if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayAzure, StringComparison.CurrentCultureIgnoreCase))
                {
                    RepositoryRegion.Enabled = false;
                    RepositoryEndpoint.Enabled = false;
                }
            }

            // Secondary repository fields
            if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayPath, StringComparison.CurrentCultureIgnoreCase))
            {
                SecondaryRepositoryLocationPicker.Visible = true;
                SecondaryRepositoryRegion.Enabled = false;
                SecondaryRepositoryEndpoint.Enabled = false;
                SecondaryRepositoryAccessKey.Enabled = false;
                SecondaryRepositorySecretKey.Enabled = false;
                SecondaryRepositoryLocation.Enabled = true;
                SecondaryBlockStoreLocation.Enabled = true;
            }
            else if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayNone, StringComparison.CurrentCultureIgnoreCase))
            {
                SecondaryRepositoryLocationPicker.Visible = false;
                SecondaryRepositoryRegion.Enabled = false;
                SecondaryRepositoryEndpoint.Enabled = false;
                SecondaryRepositoryAccessKey.Enabled = false;
                SecondaryRepositorySecretKey.Enabled = false;
                SecondaryRepositoryLocation.Enabled = false;
                SecondaryBlockStoreLocation.Enabled = false;
            }
            else
            {
                SecondaryRepositoryLocationPicker.Visible = false;
                SecondaryRepositoryRegion.Enabled = true;
                SecondaryRepositoryEndpoint.Enabled = true;
                SecondaryRepositoryAccessKey.Enabled = true;
                SecondaryRepositorySecretKey.Enabled = true;
                SecondaryRepositoryLocation.Enabled = true;
                SecondaryBlockStoreLocation.Enabled = true;
                if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayAzure, StringComparison.CurrentCultureIgnoreCase))
                {
                    SecondaryRepositoryRegion.Enabled = false;
                    SecondaryRepositoryEndpoint.Enabled = false;
                }
            }

            if (BlockStoreLocation.Text.Length > 0 && !SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayNone, StringComparison.CurrentCultureIgnoreCase))
            {
                SecondaryBlockStoreLocation.Enabled = true;
            }
            else
            {
                SecondaryBlockStoreLocation.Enabled = false;
            }

            return true;
        }

        private void RepositoryLocationPicker_Click(object sender, EventArgs e)
        {
            GeneralPicker(RepositoryLocation);
        }

        private void SecondaryRepositoryLocationPicker_Click(object sender, EventArgs e)
        {
            GeneralPicker(SecondaryRepositoryLocation);
        }

        private void SecondaryRepositoryType_SelectedIndexChanged(object sender, EventArgs e)
        {
            if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayAzure, StringComparison.CurrentCultureIgnoreCase))
            {
                tt_Secondary_Location.SetToolTip(this.SecondaryRepositoryLocation, my_config.Location_Azure_tt);
                tt_Region.SetToolTip(this.SecondaryRepositoryRegion, null);
                tt_AccessKey_OpenStack.SetToolTip(this.SecondaryRepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.SecondaryRepositoryAccessKey, my_config.General_Cloud_Provider_tt);
                tt_General_Cloud.SetToolTip(this.SecondaryRepositoryRegion, null);
            }
            else if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayS3, StringComparison.CurrentCultureIgnoreCase))
            {
                tt_Secondary_Location.SetToolTip(this.SecondaryRepositoryLocation, my_config.Location_S3_tt);
                tt_Region.SetToolTip(this.SecondaryRepositoryRegion, my_config.Region_S3_tt);
                tt_AccessKey_OpenStack.SetToolTip(this.SecondaryRepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.SecondaryRepositoryAccessKey, my_config.General_Cloud_Provider_tt);
                tt_General_Cloud.SetToolTip(this.SecondaryRepositoryRegion, null);

                if (SecondaryRepositoryEndpoint.Text.Length == 0)
                {
                    SecondaryRepositoryEndpoint.Text = @"https://s3.amazonaws.com";
                }
            }
            else if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayPath, StringComparison.CurrentCultureIgnoreCase))
            {
                tt_Region.SetToolTip(this.SecondaryRepositoryRegion, null);
                tt_Secondary_Location.SetToolTip(this.SecondaryRepositoryLocation, my_config.Location_Path_tt);
                tt_AccessKey_OpenStack.SetToolTip(this.SecondaryRepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.SecondaryRepositoryAccessKey, my_config.General_Cloud_Provider_tt);
                tt_General_Cloud.SetToolTip(this.SecondaryRepositoryRegion, null);

                if (SecondaryRepositoryLocation.Text.IndexOf("HTTP", StringComparison.CurrentCultureIgnoreCase) == 0)
                {
                    SecondaryRepositoryLocation.Text = "";
                }
            }
            else if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayOpenStack, StringComparison.CurrentCultureIgnoreCase))
            {
                tt_Region.SetToolTip(this.SecondaryRepositoryRegion, null);
                tt_Secondary_Location.SetToolTip(this.SecondaryRepositoryLocation, my_config.Location_OpenStack_tt);
                tt_AccessKey_OpenStack.SetToolTip(this.SecondaryRepositoryAccessKey, my_config.AccessKey_OpenStack_tt);
                tt_General_Cloud.SetToolTip(this.SecondaryRepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.SecondaryRepositoryRegion, my_config.General_Cloud_Provider_tt);
            }
            else
            {
                // none
                tt_Region.SetToolTip(this.SecondaryRepositoryRegion, null);
                tt_Secondary_Location.SetToolTip(this.SecondaryRepositoryLocation, null);
                tt_AccessKey_OpenStack.SetToolTip(this.SecondaryRepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.SecondaryRepositoryAccessKey, null);
                tt_General_Cloud.SetToolTip(this.SecondaryRepositoryRegion, null);
            }

            ValidateForm();
        }

        private void BlockStoreLocationPicker_Click(object sender, EventArgs e)
        {
            GeneralPicker(BlockStoreLocation);
        }

        private void LCUD_Picker_Click(object sender, EventArgs e)
        {
            GeneralPicker(RepositoryLCUDLocation);
        }

        private void GeneralPicker(System.Windows.Forms.TextBox item)
        {
            FolderBrowserDialog picker = new System.Windows.Forms.FolderBrowserDialog();

            picker.ShowNewFolderButton = false;
            picker.SelectedPath = item.Text;
            picker.RootFolder = System.Environment.SpecialFolder.MyComputer;
            SendKeys.Send("{TAB}{TAB}{RIGHT}"); // make sure that currently selected item is visible
            if (picker.ShowDialog() == DialogResult.OK)
            {
                item.Text = picker.SelectedPath;
            }
        }

        private void BlockStoreLocation_TextChanged(object sender, EventArgs e)
        {
            if (BlockStoreLocation.Text.Length > 0 && !SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayNone, StringComparison.CurrentCultureIgnoreCase))
            {
                SecondaryBlockStoreLocation.Enabled = true;
            }
            else
            {
                SecondaryBlockStoreLocation.Enabled = false;
            }
        }

        private void OK_Click(object sender, EventArgs e)
        {
            String str;

            Cursor.Current = Cursors.WaitCursor;
            Application.DoEvents();

            RegistryKey key = Registry.LocalMachine.CreateSubKey(my_config.RegistryPath);
            if (key == null)
            {
                Cursor.Current = Cursors.Default;
                Application.DoEvents();

                MessageBox.Show("Unable to open registry key", MyName,
                    MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }

            if (ValidateLocalPath(BlockStoreLocation.Text) == false)
                return;

            if(LocalLCUDLocation.Text.Equals(""))
            {
                MessageBox.Show("A local path for the LCUD path must be specified", MyName,
                    MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }

            if (ValidateLocalPath(LocalLCUDLocation.Text) == false)
                return;

            if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayNone, StringComparison.CurrentCultureIgnoreCase))
            {
                if (BlockStoreLocation.Text.Equals(""))
                {
                    Cursor.Current = Cursors.Default;
                    Application.DoEvents();
                    MessageBox.Show("Either (or both) the block store location must be defined or the primary repository, depending on whether you wish to enable block or file deduplication respectively",
                    MyName,
                    MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    key.Close();
                    return;
                }

                if (MessageBox.Show("If the primary repository is not set then file deduplication will be disabled, is that OK?",
                    MyName,
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) == DialogResult.No)
                {
                    Cursor.Current = Cursors.Default;
                    Application.DoEvents();
                    key.Close();
                    return;
                }
            }
            try
            {
                if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayPath, StringComparison.CurrentCultureIgnoreCase))
                {
                    str = my_config.RegRepositoryTypePath;
                }
                else if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayS3, StringComparison.CurrentCultureIgnoreCase))
                {
                    str = my_config.RegRepositoryTypeS3;
                }
                else if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayOpenStack, StringComparison.CurrentCultureIgnoreCase))
                {
                    str = my_config.RegRepositoryTypeOpenStack;
                }
                else if (PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayAzure, StringComparison.CurrentCultureIgnoreCase))
                {
                    str = my_config.RegRepositoryTypeAzure;
                }
                else
                {
                    Cursor.Current = Cursors.Default;
                    Application.DoEvents();

                    MessageBox.Show("Invalid repository type", MyName,
                        MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    key.Close();
                    return;
                }
                key.SetValue(my_config.RegRepositoryType, str, RegistryValueKind.String);
                key.SetValue(my_config.RegRepositoryLocation, RepositoryLocation.Text, RegistryValueKind.String);

                if (!PrimaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayPath, StringComparison.CurrentCultureIgnoreCase))
                {
                    // if NOT the path type, then store the cloud-provider fields
                    key.SetValue(my_config.RegRepositoryEndpoint, RepositoryEndpoint.Text, RegistryValueKind.String);
                    key.SetValue(my_config.RegRepositoryLocation, RepositoryLocation.Text, RegistryValueKind.String);
                    key.SetValue(my_config.RegRepositoryAccessKey, RepositoryAccessKey.Text, RegistryValueKind.String);
                    key.SetValue(my_config.RegRepositorySecretKey, RepositorySecretKey.Text, RegistryValueKind.String);
                    key.SetValue(my_config.RegRepositoryRegion, RepositoryRegion.Text, RegistryValueKind.String);
                }

                // SECONDARY repository fields
                if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayNone, StringComparison.CurrentCultureIgnoreCase))
                {
                    str = "";
                }
                else if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayPath, StringComparison.CurrentCultureIgnoreCase))
                {
                    str = my_config.RegRepositoryTypePath;
                }
                else if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayS3, StringComparison.CurrentCultureIgnoreCase))
                {
                    str = my_config.RegRepositoryTypeS3;
                }
                else if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayOpenStack, StringComparison.CurrentCultureIgnoreCase))
                {
                    str = my_config.RegRepositoryTypeOpenStack;
                }
                else if (SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayAzure, StringComparison.CurrentCultureIgnoreCase))
                {
                    str = my_config.RegRepositoryTypeAzure;
                }
                else
                {
                    Cursor.Current = Cursors.Default;
                    Application.DoEvents();

                    MessageBox.Show("Invalid repository type", MyName,
                        MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    key.Close();
                    return;
                }

                if (str.Equals(""))
                {
                    try
                    {
                        key.DeleteValue(my_config.RegSecondaryRepositoryType);
                    }
                    catch (ArgumentException) { }
                }
                else
                {
                    key.SetValue(my_config.RegSecondaryRepositoryType, str, RegistryValueKind.String);
                    if (!SecondaryRepositoryType.Text.Equals(my_config.RepositoryTypeDisplayPath, StringComparison.CurrentCultureIgnoreCase))
                    {
                        // if NOT the path type, then store the cloud-provider fields
                        key.SetValue(my_config.RegSecondaryRepositoryEndpoint, SecondaryRepositoryEndpoint.Text, RegistryValueKind.String);
                        key.SetValue(my_config.RegSecondaryRepositoryAccessKey, SecondaryRepositoryAccessKey.Text, RegistryValueKind.String);
                        key.SetValue(my_config.RegSecondaryRepositorySecretKey, SecondaryRepositorySecretKey.Text, RegistryValueKind.String);
                        key.SetValue(my_config.RegSecondaryRepositoryRegion, SecondaryRepositoryRegion.Text, RegistryValueKind.String);
                    }
                    key.SetValue(my_config.RegSecondaryRepositoryLocation, SecondaryRepositoryLocation.Text, RegistryValueKind.String);
                    key.SetValue(my_config.RegSecondaryBlockStoreLocation, SecondaryBlockStoreLocation.Text, RegistryValueKind.String);
                    if (!ValidateCloudProvider("Secondary(block store)", SecondaryRepositoryType.Text, SecondaryRepositoryLocation.Text, SecondaryRepositoryEndpoint.Text,
                        SecondaryRepositoryRegion.Text, SecondaryRepositoryAccessKey.Text, SecondaryRepositorySecretKey.Text))
                    {
                        return; // error has already been displayed to user
                    }                    
                }

                key.SetValue(my_config.RegRepositoryLCUDLocation, RepositoryLCUDLocation.Text, RegistryValueKind.String);
                key.SetValue(my_config.RegLocalLCUDLocation, LocalLCUDLocation.Text, RegistryValueKind.String);
                key.SetValue(my_config.RegResidencyThreshold, (int)FileResidencyThreshold.Value, RegistryValueKind.DWord);
                key.SetValue(my_config.RegRetentionDays, (int)RetentionDays.Value, RegistryValueKind.DWord);
                key.SetValue(my_config.RegBlockStoreLocation, BlockStoreLocation.Text);
                key.SetValue(my_config.RegDBInitialSize, (int)DBInitialSize.Value, RegistryValueKind.DWord);
                key.SetValue(my_config.RegDBGrowthSize, (int)DBGrowthSize.Value, RegistryValueKind.DWord);
                if (AdvertiseService.Checked)
                {
                    key.SetValue(my_config.RegAdvertiseService, (int)1, RegistryValueKind.DWord);
                }
                else
                {
                    key.SetValue(my_config.RegAdvertiseService, (int)0, RegistryValueKind.DWord);
                }
                if (!ValidateCloudProvider("Primary", PrimaryRepositoryType.Text, RepositoryLocation.Text, RepositoryEndpoint.Text,
                    RepositoryRegion.Text, RepositoryAccessKey.Text, RepositorySecretKey.Text))
                {
                    return; // error has already been displayed to user
                }

                key.Close();
                Cursor.Current = Cursors.Default;
                Application.DoEvents();

                MessageBox.Show("Updated registry successfully. Please re-start the service in order for the new values to be used", MyName,
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                Application.Exit(); // end program
            }
            catch(Exception ex)
            {
                MessageBox.Show("A problem occurred updating registry: " + ex.Message, MyName,
                    MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                return;
            }
        }

        public bool ValidateCloudProvider(String Instance, String Type, String Location, String Endpoint, String Region, String AccessKey, String SecretKey)
        {
            if (Type.Equals(my_config.RepositoryTypeDisplayNone, StringComparison.CurrentCultureIgnoreCase))
                return true;

            if (Type.Equals(my_config.RegRepositoryTypeAzure, StringComparison.CurrentCultureIgnoreCase))
            {
                StorageCredentials Credentials;
                CloudStorageAccount StorAccount;
                CloudBlobClient BlobAccount;
                CloudBlobContainer Container;

	            try	{
		            Credentials = new StorageCredentials(AccessKey, SecretKey);

		            StorAccount = new CloudStorageAccount(Credentials, false);

		            BlobAccount = StorAccount.CreateCloudBlobClient();

		            Container = BlobAccount.GetContainerReference(Location);

		            Container.CreateIfNotExists(BlobContainerPublicAccessType.Off);
		            }
	            catch(StorageException e)
		            {
                    MessageBox.Show(Instance + ": Unable to login to Azure account: " + e.Message, MyName,
                        MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return false;
		            }
	            catch(Exception)
		            {
                    MessageBox.Show(Instance + ": Exception when logging into Azure account: ", MyName,
                        MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return false;
                    }
            }

            if (Type.Equals(my_config.RepositoryTypeDisplayPath, StringComparison.CurrentCultureIgnoreCase))
            {
                try
                {
                    DirectoryInfo dirinfo = new DirectoryInfo(Location);
                    if (dirinfo.Exists)
                        return true;
                    Cursor.Current = Cursors.Default;
                    Application.DoEvents();
                    if (MessageBox.Show(Location + " does not exist for " + Instance + " repository, would you like to create it?", MyName,
                        MessageBoxButtons.YesNo, MessageBoxIcon.Question) == DialogResult.No)
                    {
                        return false;
                    }
                    dirinfo.Create(); // create the directory

                }
                catch (Exception ex)
                {
                    Cursor.Current = Cursors.Default;
                    Application.DoEvents();
                    MessageBox.Show(Instance + ": Unable to test directory " + Location + " error: " + ex.Message, MyName,
                        MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return false;
                }
            }

            if (Type.Equals(my_config.RepositoryTypeDisplayS3, StringComparison.CurrentCultureIgnoreCase))
            {
                try
                {
                    AmazonS3Config config = new AmazonS3Config();
                    config.ServiceURL = Endpoint;

                    if (!Region.Equals(""))
                    {
                        IEnumerable<Amazon.RegionEndpoint> listregions = Amazon.RegionEndpoint.EnumerableAllRegions;

                        foreach (Amazon.RegionEndpoint thisregion in listregions)
                        {
                            if (thisregion.SystemName.Equals(Region))
                            {
                                config.RegionEndpoint = thisregion;
                                break;
                            }
                        }
                        if (config.RegionEndpoint == null)
                        {
                            MessageBox.Show(Instance + ": Unable to locate region " + Region + ". Region can be left blank and then the endpoint used to direct the region wanted", MyName,
                                MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                            return false;
                        }
                    }
                    config.ForcePathStyle = true;
                    try
                    {
                        AmazonS3Client client = new AmazonS3Client(AccessKey, SecretKey, config);
                        if (Endpoint.Equals("") || Endpoint.Equals(@"http://s3.amazonaws.com") || Endpoint.Equals(@"https://s3.amazonaws.com"))
                        {
                            // The default endpoint allows the region to be used to force bucket to be stored elsewhere
                            // so validate the region now (if specified)
                            try
                            {
                                GetBucketLocationRequest locationreq = new GetBucketLocationRequest();
                                GetBucketLocationResponse resp;

                                locationreq.BucketName = Location;
                                resp = client.GetBucketLocation(locationreq);
                                if (resp.Location.Equals(""))
                                {
                                    if (Region.Equals("us-east-1"))
                                        return true;
                                }
                                else if (resp.Location.Equals(Region))
                                    return true;
                                Cursor.Current = Cursors.Default;
                                Application.DoEvents();
                                MessageBox.Show(Instance + ": bucket '" + Location + "' exists in '" + resp.Location.ToString() + "' not '" + Region
                                    + "'. Please amend region to correct value", MyName,
                                    MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                                return false;
                            }
                            catch (Exception)
                            {
                                // bucket does not exist -- ignore (create it next)
                            }
                        }
                        try
                        {
                            PutBucketRequest CreateBucket = new PutBucketRequest();
                            PutBucketResponse resp;

                            CreateBucket.BucketName = Location;
                            CreateBucket.UseClientRegion = true;
                            resp = client.PutBucket(CreateBucket);
                            Cursor.Current = Cursors.Default;
                            Application.DoEvents();
                            MessageBox.Show(Instance + ": bucket '" + Location + "' created successfully", MyName,
                                MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                            return true;
                        }
                        catch (AmazonS3Exception ex)
                        {
                            if (ex.ErrorCode.Equals("BucketAlreadyOwnedByYou"))
                            {
                                return true;
                            }
                            Cursor.Current = Cursors.Default;
                            Application.DoEvents();
                            MessageBox.Show(Instance + ": S3 Error for bucket " + Location + " : " + ex.Message, MyName,
                                MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                            return false;
                        }
                    }
                    catch (AmazonS3Exception ex)
                    {
                        Cursor.Current = Cursors.Default;
                        Application.DoEvents();
                        MessageBox.Show(Instance + ": Unable to connect to S3 : " + ex.Message, MyName,
                            MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                        return false;
                    }
                }
                catch (AmazonS3Exception Ex)
                {
                    Cursor.Current = Cursors.Default;
                    Application.DoEvents();
                    MessageBox.Show(Instance + ": Unable to connect to S3 : " + Ex.Message, MyName,
                        MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return false;
                }
                catch (Exception Ex)
                {
                    Cursor.Current = Cursors.Default;
                    Application.DoEvents();
                    MessageBox.Show(Instance + ": Unable to connect to S3 : " + Ex.Message, MyName,
                        MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return false;
                }
            }

            if (Type.Equals(my_config.RepositoryTypeDisplayOpenStack, StringComparison.CurrentCultureIgnoreCase))
            {
                if(AccessKey.Length == 0 || SecretKey.Length == 0)
                {
                    Cursor.Current = Cursors.Default;
                    Application.DoEvents();
                    MessageBox.Show(Instance + ": Access key and secret key must be entered", MyName,
                        MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return false;
                }

                try
                {
                    String[] Items;
                    CloudIdentityWithProject identity;
                    IIdentityProvider provider;
                    UserAccess user;
                    CloudFilesProvider files;
                    ObjectStore resp;

                    identity = new CloudIdentityWithProject();

                    Items = AccessKey.Split(':');
                    if (Items.Count() <= 1)
                    {
                        provider = new CloudIdentityProvider();
                        identity.Username = AccessKey;
                        identity.APIKey = SecretKey;
                    }
                    else
                    {
                        identity.ProjectName = Items[0];
                        identity.Username = Items[1];
                        identity.Password = SecretKey;
                        provider = new HpIdentityProvider(new Uri(Endpoint), identity);
                    }
                    user = provider.Authenticate(identity);
                    try{
                        files = new CloudFilesProvider(identity, Region, provider, null);
                        resp = files.CreateContainer(Location, null, null, false, identity);
                        // resp will be ObjectStore.ContainerCreated or ContainerExists
                        // as long as no exception, everything is good
                        if (resp == ObjectStore.ContainerCreated)
                        {
                            Cursor.Current = Cursors.Default;
                            Application.DoEvents();
                            MessageBox.Show(Instance + ": container '" + Location + "' created successfully", MyName,
                                MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                        }
                        return true;
                    }
                    catch(ResponseException Ex)
                    {
                        Cursor.Current = Cursors.Default;
                        Application.DoEvents();
                        MessageBox.Show(Instance + ": Unable to validate OpenStack container : " + Ex.Message, MyName,
                            MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                        return false;
                    }
                }
                catch (Exception Ex)
                {
                    Cursor.Current = Cursors.Default;
                    Application.DoEvents();
                    MessageBox.Show(Instance + ": Unable to connect to OpenStack provider : " + Ex.Message, MyName,
                        MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
                    return false;
                }
            }

            return true;
        }

        private void ConfigRedirection_Click(object sender, EventArgs e)
        {
            var config_form = new EnableRedirectionForm();
            config_form.ShowDialog();
        }

        private void LocalLCUDPicker_Click(object sender, EventArgs e)
        {
            GeneralPicker(LocalLCUDLocation);
        }
    }
    
}


// A class for storing constants

public static class my_config
{
    private static String regpath;

    static my_config()
    {
        regpath = ConfigurationManager.AppSettings[@"RegistryPath"];
    }

    public static String RegistryPath { get { return regpath; } }
    
    // The following values will need to be localized for display
    public static String RepositoryTypeDisplayPath { get { return @"Path"; } }
    public static String RepositoryTypeDisplayS3 { get { return @"S3"; } }
    public static String RepositoryTypeDisplayOpenStack { get { return @"OpenStack"; } }
    public static String RepositoryTypeDisplayAzure { get { return @"Azure"; } }
    public static String RepositoryTypeDisplayNone { get { return @"None"; } }

    // NOT for localization, but for storing in registry
    public static String RegAdvertiseService { get { return @"EnableServiceDiscovery"; } }

    public static String RegRepositoryType { get { return @"RepositoryType"; } }
    public static String RegRepositoryTypePath { get { return @"localFile"; } }
    public static String RegRepositoryTypeS3 { get { return @"S3"; } }
    public static String RegRepositoryTypeOpenStack { get { return @"OpenStack"; } }
    public static String RegRepositoryTypeAzure { get { return @"Azure"; } }

    public static String RegResidencyThreshold { get { return @"ResidencyThreshold"; } }
    public static String RegRetentionDays { get { return @"LimboRetentionDays"; } }

    public static String RegLocalLCUDLocation { get { return @"LocalLCUDLocation"; } }

    public static String RegRepositoryLocation { get { return @"RepositoryLocation"; } }
    public static String RegRepositoryEndpoint { get { return @"RepositoryEndpoint"; } }
    public static String RegRepositoryRegion { get { return @"RepositoryRegion"; } }
    public static String RegRepositoryAccessKey { get { return @"RepositoryAccessKey"; } }
    public static String RegRepositorySecretKey { get { return @"RepositorySecretKey"; } }
    public static String RegBlockStoreLocation { get { return @"BlockStorePath"; } }
    public static String RegRepositoryLCUDLocation { get { return @"RepositoryLCUDLocation"; } }

    // secondary repository
    public static String RegSecondaryRepositoryType { get { return @"SecondaryRepositoryType"; } }
    public static String RegSecondaryRepositoryLocation { get { return @"SecondaryRepositoryLocation"; } }
    public static String RegSecondaryRepositoryEndpoint { get { return @"SecondaryRepositoryEndpoint"; } }
    public static String RegSecondaryRepositoryRegion { get { return @"SecondaryRepositoryRegion"; } }
    public static String RegSecondaryRepositoryAccessKey { get { return @"SecondaryRepositoryAccessKey"; } }
    public static String RegSecondaryRepositorySecretKey { get { return @"SecondaryRepositorySecretKey"; } }
    public static String RegSecondaryBlockStoreLocation { get { return @"SecondaryBlockStoreLocation"; } }

    // database parameters
    public static String RegDBInitialSize { get { return @"DatabaseEnvironmentSizeMB"; } }
    public static String RegDBGrowthSize { get { return @"DatabaseEnvironmentGrowMB"; } }

    // Parameters used in redirection mode
    public static String RegConfigRedirectClientID { get { return @"ConfigRedirectClientID"; } }
    public static String RegConfigRedirectSecret { get { return @"ConfigRedirectSecret"; } }
    public static String RegConfigRedirectServer { get { return @"ConfigRedirectServer"; } }

    // Tooltip texts
    public static String DBInitialSize_tt { get { return @"Amount (in MB) for initial database creation"; } }
    public static String DBGrowthSize_tt { get { return @"Amount (in MB) to increase database size when full"; } }
    public static String ResidencyThreshold_tt { get { return @"The total number of copies of a file that must be detected before the file is considered common"; } }
    public static String RetentionDays_tt { get { return @"The number of days a file's details are kept in the database for consideration as common. Increasing will improve common-file detection at the cost of database size"; } }
    public static String AdvertiseService_tt { get { return @"When enabled, this allows clients to auto-discover/configure to use this server (recommended)"; } }
    public static String BlockStoreLocation_tt { get { return @"Set a local or UNC path here to enable block-level deduplication"; } }
    public static String Location_Path_tt { get { return @"Set a local or UNC path to use for storing common-file data"; } }
    public static String Location_S3_tt { get { return @"Set the bucket name to use for S3"; } }
    public static String Location_Azure_tt { get { return @"Set the container name to use for Microsoft Azure"; } }
    public static String Region_S3_tt { get { return @"Set the region for S3 bucket, leave blank for US-Standard region"; } }
    public static String Location_OpenStack_tt { get { return @"Set the container name for OpenStack"; } }
    public static String General_Cloud_Provider_tt { get { return @"Consult your cloud provider's documentation for proper values to use"; } }
    public static String AccessKey_OpenStack_tt { get { return @"Use account name for traditional OpenStack accounts (eg RackSpace) or Project:User for others (eg Internap/Nephoscale)"; } }
    public static String LCUD_Location_tt { get { return @"This is the local path for storing the local client-unique database files"; } }
    public static String Repository_LCUD_Location_tt { get { return @"This is where the local client-unique database files should be stored on the primary repository (not set if the primary repository is 'path')"; } }
}
