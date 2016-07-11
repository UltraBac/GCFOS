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

namespace ConfigureDeduplicationServer
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(MainForm));
            this.FileResidencyThreshold = new System.Windows.Forms.NumericUpDown();
            this.RetentionDays = new System.Windows.Forms.NumericUpDown();
            this.PrimaryRepositoryType = new System.Windows.Forms.ComboBox();
            this.RepositoryLocation = new System.Windows.Forms.TextBox();
            this.RepositoryLocationPicker = new System.Windows.Forms.Button();
            this.RepositoryRegion = new System.Windows.Forms.TextBox();
            this.RepositoryEndpoint = new System.Windows.Forms.TextBox();
            this.RepositoryAccessKey = new System.Windows.Forms.TextBox();
            this.RepositorySecretKey = new System.Windows.Forms.TextBox();
            this.SecondaryRepositoryType = new System.Windows.Forms.ComboBox();
            this.SecondaryRepositoryLocation = new System.Windows.Forms.TextBox();
            this.SecondaryRepositoryLocationPicker = new System.Windows.Forms.Button();
            this.SecondaryRepositoryRegion = new System.Windows.Forms.TextBox();
            this.SecondaryRepositoryEndpoint = new System.Windows.Forms.TextBox();
            this.SecondaryRepositoryAccessKey = new System.Windows.Forms.TextBox();
            this.SecondaryRepositorySecretKey = new System.Windows.Forms.TextBox();
            this.SecondaryBlockStoreLocation = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.label4 = new System.Windows.Forms.Label();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.label21 = new System.Windows.Forms.Label();
            this.label20 = new System.Windows.Forms.Label();
            this.label19 = new System.Windows.Forms.Label();
            this.label16 = new System.Windows.Forms.Label();
            this.label9 = new System.Windows.Forms.Label();
            this.label8 = new System.Windows.Forms.Label();
            this.label7 = new System.Windows.Forms.Label();
            this.label6 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.LocalLCUDLocation = new System.Windows.Forms.TextBox();
            this.RepositoryLCUDLocation = new System.Windows.Forms.TextBox();
            this.LocalLCUDPicker = new System.Windows.Forms.Button();
            this.BlockStoreLocation = new System.Windows.Forms.TextBox();
            this.LCUD_Picker = new System.Windows.Forms.Button();
            this.BlockStoreLocationPicker = new System.Windows.Forms.Button();
            this.label10 = new System.Windows.Forms.Label();
            this.label11 = new System.Windows.Forms.Label();
            this.label12 = new System.Windows.Forms.Label();
            this.label13 = new System.Windows.Forms.Label();
            this.label14 = new System.Windows.Forms.Label();
            this.label15 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.DBInitialSize = new System.Windows.Forms.NumericUpDown();
            this.DBGrowthSize = new System.Windows.Forms.NumericUpDown();
            this.label17 = new System.Windows.Forms.Label();
            this.label18 = new System.Windows.Forms.Label();
            this.OK = new System.Windows.Forms.Button();
            this.AdvertiseService = new System.Windows.Forms.CheckBox();
            this.ConfigRedirection = new System.Windows.Forms.Button();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            ((System.ComponentModel.ISupportInitialize)(this.FileResidencyThreshold)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.RetentionDays)).BeginInit();
            this.groupBox1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.DBInitialSize)).BeginInit();
            ((System.ComponentModel.ISupportInitialize)(this.DBGrowthSize)).BeginInit();
            this.groupBox2.SuspendLayout();
            this.SuspendLayout();
            // 
            // FileResidencyThreshold
            // 
            this.FileResidencyThreshold.Location = new System.Drawing.Point(22, 41);
            this.FileResidencyThreshold.Minimum = new decimal(new int[] {
            2,
            0,
            0,
            0});
            this.FileResidencyThreshold.Name = "FileResidencyThreshold";
            this.FileResidencyThreshold.Size = new System.Drawing.Size(120, 20);
            this.FileResidencyThreshold.TabIndex = 0;
            this.FileResidencyThreshold.Value = new decimal(new int[] {
            2,
            0,
            0,
            0});
            // 
            // RetentionDays
            // 
            this.RetentionDays.Location = new System.Drawing.Point(172, 41);
            this.RetentionDays.Maximum = new decimal(new int[] {
            365,
            0,
            0,
            0});
            this.RetentionDays.Minimum = new decimal(new int[] {
            7,
            0,
            0,
            0});
            this.RetentionDays.Name = "RetentionDays";
            this.RetentionDays.Size = new System.Drawing.Size(120, 20);
            this.RetentionDays.TabIndex = 1;
            this.RetentionDays.Value = new decimal(new int[] {
            7,
            0,
            0,
            0});
            // 
            // PrimaryRepositoryType
            // 
            this.PrimaryRepositoryType.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.PrimaryRepositoryType.FormattingEnabled = true;
            this.PrimaryRepositoryType.Location = new System.Drawing.Point(149, 19);
            this.PrimaryRepositoryType.Name = "PrimaryRepositoryType";
            this.PrimaryRepositoryType.Size = new System.Drawing.Size(121, 21);
            this.PrimaryRepositoryType.TabIndex = 1;
            this.PrimaryRepositoryType.SelectedIndexChanged += new System.EventHandler(this.PrimaryRepositoryType_SelectedIndexChanged);
            // 
            // RepositoryLocation
            // 
            this.RepositoryLocation.Location = new System.Drawing.Point(149, 46);
            this.RepositoryLocation.Name = "RepositoryLocation";
            this.RepositoryLocation.Size = new System.Drawing.Size(289, 20);
            this.RepositoryLocation.TabIndex = 2;
            // 
            // RepositoryLocationPicker
            // 
            this.RepositoryLocationPicker.Location = new System.Drawing.Point(444, 46);
            this.RepositoryLocationPicker.Name = "RepositoryLocationPicker";
            this.RepositoryLocationPicker.Size = new System.Drawing.Size(30, 20);
            this.RepositoryLocationPicker.TabIndex = 3;
            this.RepositoryLocationPicker.Text = "...";
            this.RepositoryLocationPicker.UseVisualStyleBackColor = true;
            this.RepositoryLocationPicker.Click += new System.EventHandler(this.RepositoryLocationPicker_Click);
            // 
            // RepositoryRegion
            // 
            this.RepositoryRegion.Location = new System.Drawing.Point(149, 72);
            this.RepositoryRegion.Name = "RepositoryRegion";
            this.RepositoryRegion.Size = new System.Drawing.Size(138, 20);
            this.RepositoryRegion.TabIndex = 4;
            // 
            // RepositoryEndpoint
            // 
            this.RepositoryEndpoint.Location = new System.Drawing.Point(149, 98);
            this.RepositoryEndpoint.Name = "RepositoryEndpoint";
            this.RepositoryEndpoint.Size = new System.Drawing.Size(289, 20);
            this.RepositoryEndpoint.TabIndex = 5;
            // 
            // RepositoryAccessKey
            // 
            this.RepositoryAccessKey.Location = new System.Drawing.Point(149, 124);
            this.RepositoryAccessKey.Name = "RepositoryAccessKey";
            this.RepositoryAccessKey.Size = new System.Drawing.Size(138, 20);
            this.RepositoryAccessKey.TabIndex = 6;
            // 
            // RepositorySecretKey
            // 
            this.RepositorySecretKey.Location = new System.Drawing.Point(149, 150);
            this.RepositorySecretKey.Name = "RepositorySecretKey";
            this.RepositorySecretKey.Size = new System.Drawing.Size(289, 20);
            this.RepositorySecretKey.TabIndex = 7;
            // 
            // SecondaryRepositoryType
            // 
            this.SecondaryRepositoryType.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.SecondaryRepositoryType.FormattingEnabled = true;
            this.SecondaryRepositoryType.Location = new System.Drawing.Point(145, 14);
            this.SecondaryRepositoryType.Name = "SecondaryRepositoryType";
            this.SecondaryRepositoryType.Size = new System.Drawing.Size(121, 21);
            this.SecondaryRepositoryType.TabIndex = 0;
            this.SecondaryRepositoryType.SelectedIndexChanged += new System.EventHandler(this.SecondaryRepositoryType_SelectedIndexChanged);
            // 
            // SecondaryRepositoryLocation
            // 
            this.SecondaryRepositoryLocation.Location = new System.Drawing.Point(145, 40);
            this.SecondaryRepositoryLocation.Name = "SecondaryRepositoryLocation";
            this.SecondaryRepositoryLocation.Size = new System.Drawing.Size(289, 20);
            this.SecondaryRepositoryLocation.TabIndex = 1;
            // 
            // SecondaryRepositoryLocationPicker
            // 
            this.SecondaryRepositoryLocationPicker.Location = new System.Drawing.Point(440, 40);
            this.SecondaryRepositoryLocationPicker.Name = "SecondaryRepositoryLocationPicker";
            this.SecondaryRepositoryLocationPicker.Size = new System.Drawing.Size(30, 20);
            this.SecondaryRepositoryLocationPicker.TabIndex = 2;
            this.SecondaryRepositoryLocationPicker.Text = "...";
            this.SecondaryRepositoryLocationPicker.UseVisualStyleBackColor = true;
            this.SecondaryRepositoryLocationPicker.Click += new System.EventHandler(this.SecondaryRepositoryLocationPicker_Click);
            // 
            // SecondaryRepositoryRegion
            // 
            this.SecondaryRepositoryRegion.Location = new System.Drawing.Point(145, 66);
            this.SecondaryRepositoryRegion.Name = "SecondaryRepositoryRegion";
            this.SecondaryRepositoryRegion.Size = new System.Drawing.Size(138, 20);
            this.SecondaryRepositoryRegion.TabIndex = 3;
            // 
            // SecondaryRepositoryEndpoint
            // 
            this.SecondaryRepositoryEndpoint.Location = new System.Drawing.Point(145, 95);
            this.SecondaryRepositoryEndpoint.Name = "SecondaryRepositoryEndpoint";
            this.SecondaryRepositoryEndpoint.Size = new System.Drawing.Size(289, 20);
            this.SecondaryRepositoryEndpoint.TabIndex = 4;
            // 
            // SecondaryRepositoryAccessKey
            // 
            this.SecondaryRepositoryAccessKey.Location = new System.Drawing.Point(145, 121);
            this.SecondaryRepositoryAccessKey.Name = "SecondaryRepositoryAccessKey";
            this.SecondaryRepositoryAccessKey.Size = new System.Drawing.Size(138, 20);
            this.SecondaryRepositoryAccessKey.TabIndex = 5;
            // 
            // SecondaryRepositorySecretKey
            // 
            this.SecondaryRepositorySecretKey.Location = new System.Drawing.Point(145, 147);
            this.SecondaryRepositorySecretKey.Name = "SecondaryRepositorySecretKey";
            this.SecondaryRepositorySecretKey.Size = new System.Drawing.Size(289, 20);
            this.SecondaryRepositorySecretKey.TabIndex = 6;
            // 
            // SecondaryBlockStoreLocation
            // 
            this.SecondaryBlockStoreLocation.Location = new System.Drawing.Point(145, 173);
            this.SecondaryBlockStoreLocation.Name = "SecondaryBlockStoreLocation";
            this.SecondaryBlockStoreLocation.Size = new System.Drawing.Size(289, 20);
            this.SecondaryBlockStoreLocation.TabIndex = 7;
            // 
            // label2
            // 
            this.label2.Location = new System.Drawing.Point(20, 15);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(124, 23);
            this.label2.TabIndex = 11;
            this.label2.Text = "File copy threshold";
            // 
            // label3
            // 
            this.label3.Location = new System.Drawing.Point(169, 15);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(162, 23);
            this.label3.TabIndex = 8;
            this.label3.Text = "Retention number of days";
            // 
            // label4
            // 
            this.label4.Location = new System.Drawing.Point(10, 22);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(124, 23);
            this.label4.TabIndex = 0;
            this.label4.Text = "Type";
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.label21);
            this.groupBox1.Controls.Add(this.label20);
            this.groupBox1.Controls.Add(this.label19);
            this.groupBox1.Controls.Add(this.label16);
            this.groupBox1.Controls.Add(this.label9);
            this.groupBox1.Controls.Add(this.label8);
            this.groupBox1.Controls.Add(this.label7);
            this.groupBox1.Controls.Add(this.label6);
            this.groupBox1.Controls.Add(this.label1);
            this.groupBox1.Controls.Add(this.PrimaryRepositoryType);
            this.groupBox1.Controls.Add(this.label4);
            this.groupBox1.Controls.Add(this.RepositorySecretKey);
            this.groupBox1.Controls.Add(this.LocalLCUDLocation);
            this.groupBox1.Controls.Add(this.RepositoryLCUDLocation);
            this.groupBox1.Controls.Add(this.LocalLCUDPicker);
            this.groupBox1.Controls.Add(this.BlockStoreLocation);
            this.groupBox1.Controls.Add(this.LCUD_Picker);
            this.groupBox1.Controls.Add(this.RepositoryLocation);
            this.groupBox1.Controls.Add(this.BlockStoreLocationPicker);
            this.groupBox1.Controls.Add(this.RepositoryLocationPicker);
            this.groupBox1.Controls.Add(this.RepositoryAccessKey);
            this.groupBox1.Controls.Add(this.RepositoryRegion);
            this.groupBox1.Controls.Add(this.RepositoryEndpoint);
            this.groupBox1.Location = new System.Drawing.Point(23, 105);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(499, 264);
            this.groupBox1.TabIndex = 6;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Primary Repository";
            // 
            // label21
            // 
            this.label21.AutoSize = true;
            this.label21.Location = new System.Drawing.Point(13, 232);
            this.label21.Name = "label21";
            this.label21.Size = new System.Drawing.Size(109, 13);
            this.label21.TabIndex = 9;
            this.label21.Text = "Local LCUD Location";
            // 
            // label20
            // 
            this.label20.AutoSize = true;
            this.label20.Location = new System.Drawing.Point(13, 206);
            this.label20.Name = "label20";
            this.label20.Size = new System.Drawing.Size(80, 13);
            this.label20.TabIndex = 9;
            this.label20.Text = "LCUD Location";
            // 
            // label19
            // 
            this.label19.Location = new System.Drawing.Point(0, 0);
            this.label19.Name = "label19";
            this.label19.Size = new System.Drawing.Size(100, 23);
            this.label19.TabIndex = 0;
            this.label19.Text = "Primary Repository";
            // 
            // label16
            // 
            this.label16.AutoSize = true;
            this.label16.Location = new System.Drawing.Point(13, 181);
            this.label16.Name = "label16";
            this.label16.Size = new System.Drawing.Size(106, 13);
            this.label16.TabIndex = 5;
            this.label16.Text = "Block Store Location";
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Location = new System.Drawing.Point(13, 153);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(59, 13);
            this.label9.TabIndex = 5;
            this.label9.Text = "Secret Key";
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Location = new System.Drawing.Point(13, 127);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(63, 13);
            this.label8.TabIndex = 5;
            this.label8.Text = "Access Key";
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Location = new System.Drawing.Point(13, 101);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(49, 13);
            this.label7.TabIndex = 5;
            this.label7.Text = "Endpoint";
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Location = new System.Drawing.Point(13, 72);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(41, 13);
            this.label6.TabIndex = 5;
            this.label6.Text = "Region";
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(13, 46);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(48, 13);
            this.label1.TabIndex = 5;
            this.label1.Text = "Location";
            // 
            // LocalLCUDLocation
            // 
            this.LocalLCUDLocation.Location = new System.Drawing.Point(149, 229);
            this.LocalLCUDLocation.Name = "LocalLCUDLocation";
            this.LocalLCUDLocation.Size = new System.Drawing.Size(289, 20);
            this.LocalLCUDLocation.TabIndex = 12;
            this.LocalLCUDLocation.TextChanged += new System.EventHandler(this.BlockStoreLocation_TextChanged);
            // 
            // RepositoryLCUDLocation
            // 
            this.RepositoryLCUDLocation.Location = new System.Drawing.Point(149, 203);
            this.RepositoryLCUDLocation.Name = "RepositoryLCUDLocation";
            this.RepositoryLCUDLocation.Size = new System.Drawing.Size(289, 20);
            this.RepositoryLCUDLocation.TabIndex = 10;
            this.RepositoryLCUDLocation.TextChanged += new System.EventHandler(this.BlockStoreLocation_TextChanged);
            // 
            // LocalLCUDPicker
            // 
            this.LocalLCUDPicker.Location = new System.Drawing.Point(444, 229);
            this.LocalLCUDPicker.Name = "LocalLCUDPicker";
            this.LocalLCUDPicker.Size = new System.Drawing.Size(30, 20);
            this.LocalLCUDPicker.TabIndex = 13;
            this.LocalLCUDPicker.Text = "...";
            this.LocalLCUDPicker.UseVisualStyleBackColor = true;
            this.LocalLCUDPicker.Click += new System.EventHandler(this.LocalLCUDPicker_Click);
            // 
            // BlockStoreLocation
            // 
            this.BlockStoreLocation.Location = new System.Drawing.Point(149, 177);
            this.BlockStoreLocation.Name = "BlockStoreLocation";
            this.BlockStoreLocation.Size = new System.Drawing.Size(289, 20);
            this.BlockStoreLocation.TabIndex = 8;
            this.BlockStoreLocation.TextChanged += new System.EventHandler(this.BlockStoreLocation_TextChanged);
            // 
            // LCUD_Picker
            // 
            this.LCUD_Picker.Location = new System.Drawing.Point(444, 203);
            this.LCUD_Picker.Name = "LCUD_Picker";
            this.LCUD_Picker.Size = new System.Drawing.Size(30, 20);
            this.LCUD_Picker.TabIndex = 11;
            this.LCUD_Picker.Text = "...";
            this.LCUD_Picker.UseVisualStyleBackColor = true;
            this.LCUD_Picker.Click += new System.EventHandler(this.LCUD_Picker_Click);
            // 
            // BlockStoreLocationPicker
            // 
            this.BlockStoreLocationPicker.Location = new System.Drawing.Point(444, 177);
            this.BlockStoreLocationPicker.Name = "BlockStoreLocationPicker";
            this.BlockStoreLocationPicker.Size = new System.Drawing.Size(30, 20);
            this.BlockStoreLocationPicker.TabIndex = 9;
            this.BlockStoreLocationPicker.Text = "...";
            this.BlockStoreLocationPicker.UseVisualStyleBackColor = true;
            this.BlockStoreLocationPicker.Click += new System.EventHandler(this.BlockStoreLocationPicker_Click);
            // 
            // label10
            // 
            this.label10.Location = new System.Drawing.Point(9, 17);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(124, 23);
            this.label10.TabIndex = 0;
            this.label10.Text = "Type";
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.label11.Location = new System.Drawing.Point(9, 43);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(48, 13);
            this.label11.TabIndex = 5;
            this.label11.Text = "Location";
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.Location = new System.Drawing.Point(9, 69);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(41, 13);
            this.label12.TabIndex = 5;
            this.label12.Text = "Region";
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Location = new System.Drawing.Point(9, 98);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(49, 13);
            this.label13.TabIndex = 5;
            this.label13.Text = "Endpoint";
            // 
            // label14
            // 
            this.label14.AutoSize = true;
            this.label14.Location = new System.Drawing.Point(9, 124);
            this.label14.Name = "label14";
            this.label14.Size = new System.Drawing.Size(63, 13);
            this.label14.TabIndex = 5;
            this.label14.Text = "Access Key";
            // 
            // label15
            // 
            this.label15.AutoSize = true;
            this.label15.Location = new System.Drawing.Point(9, 150);
            this.label15.Name = "label15";
            this.label15.Size = new System.Drawing.Size(59, 13);
            this.label15.TabIndex = 5;
            this.label15.Text = "Secret Key";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Location = new System.Drawing.Point(9, 176);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(132, 13);
            this.label5.TabIndex = 5;
            this.label5.Text = "Secondary Block Location";
            // 
            // DBInitialSize
            // 
            this.DBInitialSize.Increment = new decimal(new int[] {
            8,
            0,
            0,
            0});
            this.DBInitialSize.Location = new System.Drawing.Point(333, 40);
            this.DBInitialSize.Maximum = new decimal(new int[] {
            -1530494977,
            232830,
            0,
            0});
            this.DBInitialSize.Minimum = new decimal(new int[] {
            1024,
            0,
            0,
            0});
            this.DBInitialSize.Name = "DBInitialSize";
            this.DBInitialSize.Size = new System.Drawing.Size(128, 20);
            this.DBInitialSize.TabIndex = 2;
            this.DBInitialSize.Value = new decimal(new int[] {
            1024,
            0,
            0,
            0});
            // 
            // DBGrowthSize
            // 
            this.DBGrowthSize.Increment = new decimal(new int[] {
            8,
            0,
            0,
            0});
            this.DBGrowthSize.Location = new System.Drawing.Point(513, 40);
            this.DBGrowthSize.Maximum = new decimal(new int[] {
            1316134911,
            2328,
            0,
            0});
            this.DBGrowthSize.Minimum = new decimal(new int[] {
            128,
            0,
            0,
            0});
            this.DBGrowthSize.Name = "DBGrowthSize";
            this.DBGrowthSize.Size = new System.Drawing.Size(128, 20);
            this.DBGrowthSize.TabIndex = 3;
            this.DBGrowthSize.Value = new decimal(new int[] {
            128,
            0,
            0,
            0});
            // 
            // label17
            // 
            this.label17.Location = new System.Drawing.Point(330, 15);
            this.label17.Name = "label17";
            this.label17.Size = new System.Drawing.Size(162, 23);
            this.label17.TabIndex = 8;
            this.label17.Text = "Database Initial Size (MB)";
            // 
            // label18
            // 
            this.label18.Location = new System.Drawing.Point(510, 15);
            this.label18.Name = "label18";
            this.label18.Size = new System.Drawing.Size(162, 23);
            this.label18.TabIndex = 8;
            this.label18.Text = "Database Growth Size (MB)";
            // 
            // OK
            // 
            this.OK.Location = new System.Drawing.Point(566, 562);
            this.OK.Name = "OK";
            this.OK.Size = new System.Drawing.Size(75, 23);
            this.OK.TabIndex = 8;
            this.OK.Text = "OK";
            this.OK.UseVisualStyleBackColor = true;
            this.OK.Click += new System.EventHandler(this.OK_Click);
            // 
            // AdvertiseService
            // 
            this.AdvertiseService.AutoSize = true;
            this.AdvertiseService.Location = new System.Drawing.Point(23, 68);
            this.AdvertiseService.Name = "AdvertiseService";
            this.AdvertiseService.Size = new System.Drawing.Size(109, 17);
            this.AdvertiseService.TabIndex = 4;
            this.AdvertiseService.Text = "Advertise Service";
            this.AdvertiseService.UseVisualStyleBackColor = true;
            // 
            // ConfigRedirection
            // 
            this.ConfigRedirection.Location = new System.Drawing.Point(566, 78);
            this.ConfigRedirection.Name = "ConfigRedirection";
            this.ConfigRedirection.Size = new System.Drawing.Size(75, 41);
            this.ConfigRedirection.TabIndex = 5;
            this.ConfigRedirection.Text = "Configure Redirection";
            this.ConfigRedirection.UseVisualStyleBackColor = true;
            this.ConfigRedirection.Click += new System.EventHandler(this.ConfigRedirection_Click);
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.label5);
            this.groupBox2.Controls.Add(this.label15);
            this.groupBox2.Controls.Add(this.label14);
            this.groupBox2.Controls.Add(this.label13);
            this.groupBox2.Controls.Add(this.label12);
            this.groupBox2.Controls.Add(this.label11);
            this.groupBox2.Controls.Add(this.SecondaryBlockStoreLocation);
            this.groupBox2.Controls.Add(this.SecondaryRepositorySecretKey);
            this.groupBox2.Controls.Add(this.label10);
            this.groupBox2.Controls.Add(this.SecondaryRepositoryAccessKey);
            this.groupBox2.Controls.Add(this.SecondaryRepositoryEndpoint);
            this.groupBox2.Controls.Add(this.SecondaryRepositoryRegion);
            this.groupBox2.Controls.Add(this.SecondaryRepositoryLocationPicker);
            this.groupBox2.Controls.Add(this.SecondaryRepositoryLocation);
            this.groupBox2.Controls.Add(this.SecondaryRepositoryType);
            this.groupBox2.Location = new System.Drawing.Point(23, 385);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(499, 204);
            this.groupBox2.TabIndex = 7;
            this.groupBox2.TabStop = false;
            this.groupBox2.Text = "Secondary Repository";
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(665, 601);
            this.Controls.Add(this.groupBox2);
            this.Controls.Add(this.ConfigRedirection);
            this.Controls.Add(this.AdvertiseService);
            this.Controls.Add(this.OK);
            this.Controls.Add(this.DBGrowthSize);
            this.Controls.Add(this.DBInitialSize);
            this.Controls.Add(this.label18);
            this.Controls.Add(this.label17);
            this.Controls.Add(this.label3);
            this.Controls.Add(this.label2);
            this.Controls.Add(this.RetentionDays);
            this.Controls.Add(this.FileResidencyThreshold);
            this.Controls.Add(this.groupBox1);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "MainForm";
            this.Text = "Configure Deduplication Server";
            this.Load += new System.EventHandler(this.Form1_Load);
            ((System.ComponentModel.ISupportInitialize)(this.FileResidencyThreshold)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.RetentionDays)).EndInit();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            ((System.ComponentModel.ISupportInitialize)(this.DBInitialSize)).EndInit();
            ((System.ComponentModel.ISupportInitialize)(this.DBGrowthSize)).EndInit();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.NumericUpDown FileResidencyThreshold;
        private System.Windows.Forms.NumericUpDown RetentionDays;
        private System.Windows.Forms.ComboBox PrimaryRepositoryType;
        private System.Windows.Forms.TextBox RepositoryLocation;
        private System.Windows.Forms.Button RepositoryLocationPicker;
        private System.Windows.Forms.TextBox RepositoryRegion;
        private System.Windows.Forms.TextBox RepositoryEndpoint;
        private System.Windows.Forms.TextBox RepositoryAccessKey;
        private System.Windows.Forms.TextBox RepositorySecretKey;
        private System.Windows.Forms.ComboBox SecondaryRepositoryType;
        private System.Windows.Forms.TextBox SecondaryRepositoryLocation;
        private System.Windows.Forms.Button SecondaryRepositoryLocationPicker;
        private System.Windows.Forms.TextBox SecondaryRepositoryRegion;
        private System.Windows.Forms.TextBox SecondaryRepositoryEndpoint;
        private System.Windows.Forms.TextBox SecondaryRepositoryAccessKey;
        private System.Windows.Forms.TextBox SecondaryRepositorySecretKey;
        private System.Windows.Forms.TextBox SecondaryBlockStoreLocation;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.Label label9;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.Label label11;
        private System.Windows.Forms.Label label12;
        private System.Windows.Forms.Label label13;
        private System.Windows.Forms.Label label14;
        private System.Windows.Forms.Label label15;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.Label label16;
        private System.Windows.Forms.TextBox BlockStoreLocation;
        private System.Windows.Forms.Button BlockStoreLocationPicker;
        private System.Windows.Forms.NumericUpDown DBInitialSize;
        private System.Windows.Forms.NumericUpDown DBGrowthSize;
        private System.Windows.Forms.Label label17;
        private System.Windows.Forms.Label label18;
        private System.Windows.Forms.Button OK;
        private System.Windows.Forms.CheckBox AdvertiseService;
        private System.Windows.Forms.Button ConfigRedirection;
        private System.Windows.Forms.Label label19;
        private System.Windows.Forms.TextBox RepositoryLCUDLocation;
        private System.Windows.Forms.Button LCUD_Picker;
        private System.Windows.Forms.Label label20;
        private System.Windows.Forms.Label label21;
        private System.Windows.Forms.TextBox LocalLCUDLocation;
        private System.Windows.Forms.Button LocalLCUDPicker;
        private System.Windows.Forms.GroupBox groupBox2;
    }
}

