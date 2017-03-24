﻿namespace DesktopTestApp
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
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.acquireTabPage = new System.Windows.Forms.TabPage();
            this.groupBox2 = new System.Windows.Forms.GroupBox();
            this.never = new System.Windows.Forms.RadioButton();
            this.consent = new System.Windows.Forms.RadioButton();
            this.forceLogin = new System.Windows.Forms.RadioButton();
            this.selectAccount = new System.Windows.Forms.RadioButton();
            this.callResult = new System.Windows.Forms.TextBox();
            this.label8 = new System.Windows.Forms.Label();
            this.userList = new System.Windows.Forms.ComboBox();
            this.label7 = new System.Windows.Forms.Label();
            this.acquireTokenSilent = new System.Windows.Forms.Button();
            this.acquireTokenInteractive = new System.Windows.Forms.Button();
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.validateAuthorityDisabled = new System.Windows.Forms.RadioButton();
            this.validateAuthorityEnabled = new System.Windows.Forms.RadioButton();
            this.loginHint = new System.Windows.Forms.TextBox();
            this.label6 = new System.Windows.Forms.Label();
            this.label5 = new System.Windows.Forms.Label();
            this.overridenAuthority = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.authority = new System.Windows.Forms.ComboBox();
            this.label3 = new System.Windows.Forms.Label();
            this.settingsTabPage = new System.Windows.Forms.TabPage();
            this.cacheTabPage = new System.Windows.Forms.TabPage();
            this.logsTabPage = new System.Windows.Forms.TabPage();
            this.button1 = new System.Windows.Forms.Button();
            this.msalPIILogs = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.msalLogs = new System.Windows.Forms.TextBox();
            this.acquire = new System.Windows.Forms.Button();
            this.settings = new System.Windows.Forms.Button();
            this.cache = new System.Windows.Forms.Button();
            this.logs = new System.Windows.Forms.Button();
            this.scopes = new System.Windows.Forms.TextBox();
            this.label9 = new System.Windows.Forms.Label();
            this.tabControl1.SuspendLayout();
            this.acquireTabPage.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.logsTabPage.SuspendLayout();
            this.SuspendLayout();
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.acquireTabPage);
            this.tabControl1.Controls.Add(this.settingsTabPage);
            this.tabControl1.Controls.Add(this.cacheTabPage);
            this.tabControl1.Controls.Add(this.logsTabPage);
            this.tabControl1.Location = new System.Drawing.Point(1, 1);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(676, 814);
            this.tabControl1.TabIndex = 0;
            // 
            // acquireTabPage
            // 
            this.acquireTabPage.BackColor = System.Drawing.SystemColors.Control;
            this.acquireTabPage.Controls.Add(this.scopes);
            this.acquireTabPage.Controls.Add(this.label9);
            this.acquireTabPage.Controls.Add(this.groupBox2);
            this.acquireTabPage.Controls.Add(this.callResult);
            this.acquireTabPage.Controls.Add(this.label8);
            this.acquireTabPage.Controls.Add(this.userList);
            this.acquireTabPage.Controls.Add(this.label7);
            this.acquireTabPage.Controls.Add(this.acquireTokenSilent);
            this.acquireTabPage.Controls.Add(this.acquireTokenInteractive);
            this.acquireTabPage.Controls.Add(this.groupBox1);
            this.acquireTabPage.Controls.Add(this.loginHint);
            this.acquireTabPage.Controls.Add(this.label6);
            this.acquireTabPage.Controls.Add(this.label5);
            this.acquireTabPage.Controls.Add(this.overridenAuthority);
            this.acquireTabPage.Controls.Add(this.label4);
            this.acquireTabPage.Controls.Add(this.authority);
            this.acquireTabPage.Controls.Add(this.label3);
            this.acquireTabPage.Location = new System.Drawing.Point(4, 22);
            this.acquireTabPage.Name = "acquireTabPage";
            this.acquireTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.acquireTabPage.Size = new System.Drawing.Size(668, 788);
            this.acquireTabPage.TabIndex = 0;
            this.acquireTabPage.Text = "acquireTabPage";
            // 
            // groupBox2
            // 
            this.groupBox2.Controls.Add(this.never);
            this.groupBox2.Controls.Add(this.consent);
            this.groupBox2.Controls.Add(this.forceLogin);
            this.groupBox2.Controls.Add(this.selectAccount);
            this.groupBox2.Location = new System.Drawing.Point(256, 154);
            this.groupBox2.Name = "groupBox2";
            this.groupBox2.Size = new System.Drawing.Size(332, 51);
            this.groupBox2.TabIndex = 10;
            this.groupBox2.TabStop = false;
            // 
            // never
            // 
            this.never.AutoSize = true;
            this.never.Location = new System.Drawing.Point(267, 18);
            this.never.Name = "never";
            this.never.Size = new System.Drawing.Size(54, 17);
            this.never.TabIndex = 10;
            this.never.Text = "Never";
            this.never.UseVisualStyleBackColor = true;
            // 
            // consent
            // 
            this.consent.AutoSize = true;
            this.consent.Location = new System.Drawing.Point(197, 18);
            this.consent.Name = "consent";
            this.consent.Size = new System.Drawing.Size(64, 17);
            this.consent.TabIndex = 9;
            this.consent.Text = "Consent";
            this.consent.UseVisualStyleBackColor = true;
            // 
            // forceLogin
            // 
            this.forceLogin.AutoSize = true;
            this.forceLogin.Location = new System.Drawing.Point(110, 18);
            this.forceLogin.Name = "forceLogin";
            this.forceLogin.Size = new System.Drawing.Size(81, 17);
            this.forceLogin.TabIndex = 8;
            this.forceLogin.Text = "Force Login";
            this.forceLogin.UseVisualStyleBackColor = true;
            // 
            // selectAccount
            // 
            this.selectAccount.AutoSize = true;
            this.selectAccount.Checked = true;
            this.selectAccount.Location = new System.Drawing.Point(6, 19);
            this.selectAccount.Name = "selectAccount";
            this.selectAccount.Size = new System.Drawing.Size(98, 17);
            this.selectAccount.TabIndex = 7;
            this.selectAccount.TabStop = true;
            this.selectAccount.Text = "Select Account";
            this.selectAccount.UseVisualStyleBackColor = true;
            // 
            // callResult
            // 
            this.callResult.Location = new System.Drawing.Point(12, 352);
            this.callResult.Multiline = true;
            this.callResult.Name = "callResult";
            this.callResult.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.callResult.Size = new System.Drawing.Size(645, 353);
            this.callResult.TabIndex = 13;
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label8.Location = new System.Drawing.Point(8, 172);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(106, 24);
            this.label8.TabIndex = 9;
            this.label8.Text = "UI Behavior";
            // 
            // userList
            // 
            this.userList.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.userList.FormattingEnabled = true;
            this.userList.Location = new System.Drawing.Point(256, 266);
            this.userList.Name = "userList";
            this.userList.Size = new System.Drawing.Size(352, 21);
            this.userList.TabIndex = 12;
            // 
            // label7
            // 
            this.label7.AutoSize = true;
            this.label7.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label7.Location = new System.Drawing.Point(8, 266);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(49, 24);
            this.label7.TabIndex = 11;
            this.label7.Text = "User";
            // 
            // acquireTokenSilent
            // 
            this.acquireTokenSilent.Location = new System.Drawing.Point(444, 711);
            this.acquireTokenSilent.Name = "acquireTokenSilent";
            this.acquireTokenSilent.Size = new System.Drawing.Size(164, 46);
            this.acquireTokenSilent.TabIndex = 10;
            this.acquireTokenSilent.Text = "Acquire Token Silent";
            this.acquireTokenSilent.UseVisualStyleBackColor = true;
            // 
            // acquireTokenInteractive
            // 
            this.acquireTokenInteractive.Location = new System.Drawing.Point(42, 711);
            this.acquireTokenInteractive.Name = "acquireTokenInteractive";
            this.acquireTokenInteractive.Size = new System.Drawing.Size(164, 46);
            this.acquireTokenInteractive.TabIndex = 9;
            this.acquireTokenInteractive.Text = "Acquire Token Interactive";
            this.acquireTokenInteractive.UseVisualStyleBackColor = true;
            this.acquireTokenInteractive.Click += new System.EventHandler(this.acquireTokenInteractive_Click);
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.validateAuthorityDisabled);
            this.groupBox1.Controls.Add(this.validateAuthorityEnabled);
            this.groupBox1.Location = new System.Drawing.Point(256, 91);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(205, 51);
            this.groupBox1.TabIndex = 8;
            this.groupBox1.TabStop = false;
            // 
            // validateAuthorityDisabled
            // 
            this.validateAuthorityDisabled.AutoSize = true;
            this.validateAuthorityDisabled.Location = new System.Drawing.Point(134, 18);
            this.validateAuthorityDisabled.Name = "validateAuthorityDisabled";
            this.validateAuthorityDisabled.Size = new System.Drawing.Size(66, 17);
            this.validateAuthorityDisabled.TabIndex = 8;
            this.validateAuthorityDisabled.Text = "Disabled";
            this.validateAuthorityDisabled.UseVisualStyleBackColor = true;
            // 
            // validateAuthorityEnabled
            // 
            this.validateAuthorityEnabled.AutoSize = true;
            this.validateAuthorityEnabled.Checked = true;
            this.validateAuthorityEnabled.Location = new System.Drawing.Point(6, 19);
            this.validateAuthorityEnabled.Name = "validateAuthorityEnabled";
            this.validateAuthorityEnabled.Size = new System.Drawing.Size(64, 17);
            this.validateAuthorityEnabled.TabIndex = 7;
            this.validateAuthorityEnabled.TabStop = true;
            this.validateAuthorityEnabled.Text = "Enabled";
            this.validateAuthorityEnabled.UseVisualStyleBackColor = true;
            // 
            // loginHint
            // 
            this.loginHint.Location = new System.Drawing.Point(256, 226);
            this.loginHint.Name = "loginHint";
            this.loginHint.Size = new System.Drawing.Size(352, 20);
            this.loginHint.TabIndex = 6;
            // 
            // label6
            // 
            this.label6.AutoSize = true;
            this.label6.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label6.Location = new System.Drawing.Point(8, 228);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(95, 24);
            this.label6.TabIndex = 5;
            this.label6.Text = "Login Hint";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label5.Location = new System.Drawing.Point(8, 109);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(155, 24);
            this.label5.TabIndex = 4;
            this.label5.Text = "Validate Authority";
            // 
            // overridenAuthority
            // 
            this.overridenAuthority.Location = new System.Drawing.Point(256, 59);
            this.overridenAuthority.Name = "overridenAuthority";
            this.overridenAuthority.Size = new System.Drawing.Size(352, 20);
            this.overridenAuthority.TabIndex = 3;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(8, 58);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(246, 24);
            this.label4.TabIndex = 2;
            this.label4.Text = "Overriden Authority for 1 call";
            // 
            // authority
            // 
            this.authority.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.authority.FormattingEnabled = true;
            this.authority.Items.AddRange(new object[] {
            "https://login.microsoftonline.com/common",
            "https://login.microsoftonline.de/common",
            "https://login.microsoftonline.us/common",
            "https://​login-us.microsoftonline.com/common",
            "https://login.chinacloudapi.cn/common"});
            this.authority.Location = new System.Drawing.Point(256, 19);
            this.authority.Name = "authority";
            this.authority.Size = new System.Drawing.Size(352, 21);
            this.authority.TabIndex = 1;
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label3.Location = new System.Drawing.Point(8, 19);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(83, 24);
            this.label3.TabIndex = 0;
            this.label3.Text = "Authority";
            // 
            // settingsTabPage
            // 
            this.settingsTabPage.Location = new System.Drawing.Point(4, 22);
            this.settingsTabPage.Name = "settingsTabPage";
            this.settingsTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.settingsTabPage.Size = new System.Drawing.Size(668, 788);
            this.settingsTabPage.TabIndex = 1;
            this.settingsTabPage.Text = "settingsTabPage";
            this.settingsTabPage.UseVisualStyleBackColor = true;
            // 
            // cacheTabPage
            // 
            this.cacheTabPage.Location = new System.Drawing.Point(4, 22);
            this.cacheTabPage.Name = "cacheTabPage";
            this.cacheTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.cacheTabPage.Size = new System.Drawing.Size(668, 788);
            this.cacheTabPage.TabIndex = 2;
            this.cacheTabPage.Text = "cacheTabPage";
            this.cacheTabPage.UseVisualStyleBackColor = true;
            // 
            // logsTabPage
            // 
            this.logsTabPage.Controls.Add(this.button1);
            this.logsTabPage.Controls.Add(this.msalPIILogs);
            this.logsTabPage.Controls.Add(this.label2);
            this.logsTabPage.Controls.Add(this.label1);
            this.logsTabPage.Controls.Add(this.msalLogs);
            this.logsTabPage.Location = new System.Drawing.Point(4, 22);
            this.logsTabPage.Name = "logsTabPage";
            this.logsTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.logsTabPage.Size = new System.Drawing.Size(668, 788);
            this.logsTabPage.TabIndex = 3;
            this.logsTabPage.Text = "logsTabPage";
            this.logsTabPage.UseVisualStyleBackColor = true;
            // 
            // button1
            // 
            this.button1.Location = new System.Drawing.Point(223, 692);
            this.button1.Name = "button1";
            this.button1.Size = new System.Drawing.Size(151, 43);
            this.button1.TabIndex = 4;
            this.button1.Text = "Clear Logs";
            this.button1.UseVisualStyleBackColor = true;
            // 
            // msalPIILogs
            // 
            this.msalPIILogs.Location = new System.Drawing.Point(7, 365);
            this.msalPIILogs.Multiline = true;
            this.msalPIILogs.Name = "msalPIILogs";
            this.msalPIILogs.ReadOnly = true;
            this.msalPIILogs.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.msalPIILogs.Size = new System.Drawing.Size(655, 304);
            this.msalPIILogs.TabIndex = 3;
            // 
            // label2
            // 
            this.label2.AutoSize = true;
            this.label2.Location = new System.Drawing.Point(143, 5);
            this.label2.Name = "label2";
            this.label2.Size = new System.Drawing.Size(336, 13);
            this.label2.TabIndex = 2;
            this.label2.Text = "========================= Logs =========================";
            this.label2.Click += new System.EventHandler(this.label2_Click);
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(143, 349);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(352, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "========================= PII Logs =========================";
            this.label1.Click += new System.EventHandler(this.label1_Click);
            // 
            // msalLogs
            // 
            this.msalLogs.Location = new System.Drawing.Point(7, 21);
            this.msalLogs.Multiline = true;
            this.msalLogs.Name = "msalLogs";
            this.msalLogs.ReadOnly = true;
            this.msalLogs.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.msalLogs.Size = new System.Drawing.Size(655, 304);
            this.msalLogs.TabIndex = 0;
            // 
            // acquire
            // 
            this.acquire.Location = new System.Drawing.Point(1, 817);
            this.acquire.Name = "acquire";
            this.acquire.Size = new System.Drawing.Size(151, 45);
            this.acquire.TabIndex = 1;
            this.acquire.Text = "Acquire";
            this.acquire.UseVisualStyleBackColor = true;
            this.acquire.Click += new System.EventHandler(this.acquire_Click);
            // 
            // settings
            // 
            this.settings.Location = new System.Drawing.Point(173, 817);
            this.settings.Name = "settings";
            this.settings.Size = new System.Drawing.Size(151, 45);
            this.settings.TabIndex = 2;
            this.settings.Text = "Settings";
            this.settings.UseVisualStyleBackColor = true;
            this.settings.Click += new System.EventHandler(this.settings_Click);
            // 
            // cache
            // 
            this.cache.Location = new System.Drawing.Point(349, 817);
            this.cache.Name = "cache";
            this.cache.Size = new System.Drawing.Size(151, 45);
            this.cache.TabIndex = 3;
            this.cache.Text = "Cache";
            this.cache.UseVisualStyleBackColor = true;
            this.cache.Click += new System.EventHandler(this.cache_Click);
            // 
            // logs
            // 
            this.logs.Location = new System.Drawing.Point(522, 817);
            this.logs.Name = "logs";
            this.logs.Size = new System.Drawing.Size(151, 45);
            this.logs.TabIndex = 4;
            this.logs.Text = "Logs";
            this.logs.UseVisualStyleBackColor = true;
            this.logs.Click += new System.EventHandler(this.logs_Click);
            // 
            // scopes
            // 
            this.scopes.Location = new System.Drawing.Point(256, 310);
            this.scopes.Name = "scopes";
            this.scopes.Size = new System.Drawing.Size(352, 20);
            this.scopes.TabIndex = 15;
            this.scopes.Text = "mail.read";
            // 
            // label9
            // 
            this.label9.AutoSize = true;
            this.label9.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label9.Location = new System.Drawing.Point(8, 312);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(74, 24);
            this.label9.TabIndex = 14;
            this.label9.Text = "Scopes";
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(674, 863);
            this.Controls.Add(this.logs);
            this.Controls.Add(this.cache);
            this.Controls.Add(this.settings);
            this.Controls.Add(this.acquire);
            this.Controls.Add(this.tabControl1);
            this.MaximizeBox = false;
            this.Name = "MainForm";
            this.Text = "Dev Utility Test App";
            this.tabControl1.ResumeLayout(false);
            this.acquireTabPage.ResumeLayout(false);
            this.acquireTabPage.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.logsTabPage.ResumeLayout(false);
            this.logsTabPage.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage acquireTabPage;
        private System.Windows.Forms.TabPage settingsTabPage;
        private System.Windows.Forms.Button acquire;
        private System.Windows.Forms.Button settings;
        private System.Windows.Forms.Button cache;
        private System.Windows.Forms.Button logs;
        private System.Windows.Forms.TabPage cacheTabPage;
        private System.Windows.Forms.TabPage logsTabPage;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.TextBox msalLogs;
        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.TextBox msalPIILogs;
        private System.Windows.Forms.Button button1;
        private System.Windows.Forms.Label label3;
        private System.Windows.Forms.ComboBox authority;
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox overridenAuthority;
        private System.Windows.Forms.Label label5;
        private System.Windows.Forms.TextBox loginHint;
        private System.Windows.Forms.Label label6;
        private System.Windows.Forms.RadioButton validateAuthorityEnabled;
        private System.Windows.Forms.GroupBox groupBox1;
        private System.Windows.Forms.RadioButton validateAuthorityDisabled;
        private System.Windows.Forms.Button acquireTokenSilent;
        private System.Windows.Forms.Button acquireTokenInteractive;
        private System.Windows.Forms.ComboBox userList;
        private System.Windows.Forms.Label label7;
        private System.Windows.Forms.TextBox callResult;
        private System.Windows.Forms.GroupBox groupBox2;
        private System.Windows.Forms.RadioButton forceLogin;
        private System.Windows.Forms.RadioButton selectAccount;
        private System.Windows.Forms.Label label8;
        private System.Windows.Forms.RadioButton never;
        private System.Windows.Forms.RadioButton consent;
        private System.Windows.Forms.TextBox scopes;
        private System.Windows.Forms.Label label9;
    }
}

