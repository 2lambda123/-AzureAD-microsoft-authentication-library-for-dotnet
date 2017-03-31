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
            this.authority = new System.Windows.Forms.TextBox();
            this.extraQueryParams = new System.Windows.Forms.TextBox();
            this.environmentQP = new System.Windows.Forms.TextBox();
            this.tabControl1 = new System.Windows.Forms.TabControl();
            this.publicClientTabPage = new System.Windows.Forms.TabPage();
            this.IdTokenResult = new System.Windows.Forms.TextBox();
            this.accessTokenResult = new System.Windows.Forms.TextBox();
            this.label12 = new System.Windows.Forms.Label();
            this.PiiLoggingDisabled = new System.Windows.Forms.RadioButton();
            this.PiiLoggingEnabled = new System.Windows.Forms.RadioButton();
            this.PiiLoggingLabel = new System.Windows.Forms.Label();
            this.ScopeResult = new System.Windows.Forms.ListBox();
            this.Scope = new System.Windows.Forms.Label();
            this.IdToken = new System.Windows.Forms.Label();
            this.UserResult = new System.Windows.Forms.Label();
            this.User = new System.Windows.Forms.Label();
            this.TenantIdResult = new System.Windows.Forms.Label();
            this.TenantId = new System.Windows.Forms.Label();
            this.ExpiresOnResult = new System.Windows.Forms.Label();
            this.ExpiresOn = new System.Windows.Forms.Label();
            this.AccessToken = new System.Windows.Forms.Label();
            this.scopes = new System.Windows.Forms.TextBox();
            this.label9 = new System.Windows.Forms.Label();
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
            this.overriddenAuthority = new System.Windows.Forms.TextBox();
            this.label4 = new System.Windows.Forms.Label();
            this.label3 = new System.Windows.Forms.Label();
            this.settingsTabPage = new System.Windows.Forms.TabPage();
            this.label11 = new System.Windows.Forms.Label();
            this.applySettings = new System.Windows.Forms.Button();
            this.label10 = new System.Windows.Forms.Label();
            this.cacheTabPage = new System.Windows.Forms.TabPage();
            this.ExpiresOnResultInCache = new System.Windows.Forms.Label();
            this.ExpiresOnInCache = new System.Windows.Forms.Label();
            this.UserResultInCache = new System.Windows.Forms.Label();
            this.UserInCache = new System.Windows.Forms.Label();
            this.AccessTokenResultInCache = new System.Windows.Forms.TextBox();
            this.ExpireAccessTokenBtn = new System.Windows.Forms.Button();
            this.logsTabPage = new System.Windows.Forms.TabPage();
            this.button1 = new System.Windows.Forms.Button();
            this.msalPIILogs = new System.Windows.Forms.TextBox();
            this.label2 = new System.Windows.Forms.Label();
            this.label1 = new System.Windows.Forms.Label();
            this.msalLogs = new System.Windows.Forms.TextBox();
            this.confidentialClientTabPage = new System.Windows.Forms.TabPage();
            this.confClientAcquireTokenSilentBtn = new System.Windows.Forms.Button();
            this.confClientAcquireTokenBtn = new System.Windows.Forms.Button();
            this.confClientPiiEnabledButton = new System.Windows.Forms.RadioButton();
            this.confClientPiiDisabledButton = new System.Windows.Forms.RadioButton();
            this.confClientPiiEnabledLabel = new System.Windows.Forms.Label();
            this.confClientScopesResult = new System.Windows.Forms.ListBox();
            this.conClientScopesLabel = new System.Windows.Forms.Label();
            this.confClientIdTokenLabel = new System.Windows.Forms.Label();
            this.confClientUserResult = new System.Windows.Forms.Label();
            this.conClientUserLabel = new System.Windows.Forms.Label();
            this.confClientTenantIdResult = new System.Windows.Forms.Label();
            this.confClientTenantIdLabel = new System.Windows.Forms.Label();
            this.confClientExpiresOnResult = new System.Windows.Forms.Label();
            this.confClientExpiresOnLabel = new System.Windows.Forms.Label();
            this.confClientAccessTokenResult = new System.Windows.Forms.TextBox();
            this.confClientAccessTokenLabel = new System.Windows.Forms.Label();
            this.callResultConfClient = new System.Windows.Forms.TextBox();
            this.ConfClientScopesBox = new System.Windows.Forms.ListView();
            this.ConfClientScopesLabel = new System.Windows.Forms.Label();
            this.ConfClientUserBox = new System.Windows.Forms.TextBox();
            this.ConfClientUserLabel = new System.Windows.Forms.Label();
            this.ConfClientLoginHintBox = new System.Windows.Forms.TextBox();
            this.ConfClientLoginHintLabel = new System.Windows.Forms.Label();
            this.ConfClientNeverButton = new System.Windows.Forms.RadioButton();
            this.ConfClientConsentButton = new System.Windows.Forms.RadioButton();
            this.ConfClientForceLoginButton = new System.Windows.Forms.RadioButton();
            this.ConfClientSelectAccountButton = new System.Windows.Forms.RadioButton();
            this.ConfClientUiBehaviorLabel = new System.Windows.Forms.Label();
            this.ConfClientValidateAuthorityDisabled = new System.Windows.Forms.RadioButton();
            this.ConfClientValidateAuthorityEnabled = new System.Windows.Forms.RadioButton();
            this.ConfClientValidateAuthorityLabel = new System.Windows.Forms.Label();
            this.ConfClientOverrideAuthority = new System.Windows.Forms.TextBox();
            this.label13 = new System.Windows.Forms.Label();
            this.ConfClientAuthority = new System.Windows.Forms.Label();
            this.CcAuthorityLabel = new System.Windows.Forms.Label();
            this.publicClient = new System.Windows.Forms.Button();
            this.settings = new System.Windows.Forms.Button();
            this.cache = new System.Windows.Forms.Button();
            this.logs = new System.Windows.Forms.Button();
            this.confidentialClient = new System.Windows.Forms.Button();
            this.ConfClientIdTokenResult = new System.Windows.Forms.TextBox();
            this.tabControl1.SuspendLayout();
            this.publicClientTabPage.SuspendLayout();
            this.groupBox2.SuspendLayout();
            this.groupBox1.SuspendLayout();
            this.settingsTabPage.SuspendLayout();
            this.cacheTabPage.SuspendLayout();
            this.logsTabPage.SuspendLayout();
            this.confidentialClientTabPage.SuspendLayout();
            this.SuspendLayout();
            // 
            // authority
            // 
            this.authority.AccessibleName = "authority";
            this.authority.Location = new System.Drawing.Point(256, 19);
            this.authority.Name = "authority";
            this.authority.Size = new System.Drawing.Size(352, 20);
            this.authority.TabIndex = 16;
            this.authority.Text = "https://login.microsoftonline.com/common";
            // 
            // extraQueryParams
            // 
            this.extraQueryParams.AccessibleName = "";
            this.extraQueryParams.Location = new System.Drawing.Point(248, 90);
            this.extraQueryParams.Name = "extraQueryParams";
            this.extraQueryParams.Size = new System.Drawing.Size(352, 20);
            this.extraQueryParams.TabIndex = 21;
            // 
            // environmentQP
            // 
            this.environmentQP.AccessibleName = "";
            this.environmentQP.Location = new System.Drawing.Point(248, 32);
            this.environmentQP.Name = "environmentQP";
            this.environmentQP.Size = new System.Drawing.Size(352, 20);
            this.environmentQP.TabIndex = 18;
            // 
            // tabControl1
            // 
            this.tabControl1.Controls.Add(this.publicClientTabPage);
            this.tabControl1.Controls.Add(this.settingsTabPage);
            this.tabControl1.Controls.Add(this.cacheTabPage);
            this.tabControl1.Controls.Add(this.logsTabPage);
            this.tabControl1.Controls.Add(this.confidentialClientTabPage);
            this.tabControl1.Location = new System.Drawing.Point(1, -3);
            this.tabControl1.Name = "tabControl1";
            this.tabControl1.RightToLeftLayout = true;
            this.tabControl1.SelectedIndex = 0;
            this.tabControl1.Size = new System.Drawing.Size(676, 814);
            this.tabControl1.TabIndex = 0;
            // 
            // publicClientTabPage
            // 
            this.publicClientTabPage.BackColor = System.Drawing.SystemColors.Control;
            this.publicClientTabPage.Controls.Add(this.IdTokenResult);
            this.publicClientTabPage.Controls.Add(this.accessTokenResult);
            this.publicClientTabPage.Controls.Add(this.label12);
            this.publicClientTabPage.Controls.Add(this.PiiLoggingDisabled);
            this.publicClientTabPage.Controls.Add(this.PiiLoggingEnabled);
            this.publicClientTabPage.Controls.Add(this.PiiLoggingLabel);
            this.publicClientTabPage.Controls.Add(this.ScopeResult);
            this.publicClientTabPage.Controls.Add(this.Scope);
            this.publicClientTabPage.Controls.Add(this.IdToken);
            this.publicClientTabPage.Controls.Add(this.UserResult);
            this.publicClientTabPage.Controls.Add(this.User);
            this.publicClientTabPage.Controls.Add(this.TenantIdResult);
            this.publicClientTabPage.Controls.Add(this.TenantId);
            this.publicClientTabPage.Controls.Add(this.ExpiresOnResult);
            this.publicClientTabPage.Controls.Add(this.ExpiresOn);
            this.publicClientTabPage.Controls.Add(this.AccessToken);
            this.publicClientTabPage.Controls.Add(this.authority);
            this.publicClientTabPage.Controls.Add(this.scopes);
            this.publicClientTabPage.Controls.Add(this.label9);
            this.publicClientTabPage.Controls.Add(this.groupBox2);
            this.publicClientTabPage.Controls.Add(this.callResult);
            this.publicClientTabPage.Controls.Add(this.label8);
            this.publicClientTabPage.Controls.Add(this.userList);
            this.publicClientTabPage.Controls.Add(this.label7);
            this.publicClientTabPage.Controls.Add(this.acquireTokenSilent);
            this.publicClientTabPage.Controls.Add(this.acquireTokenInteractive);
            this.publicClientTabPage.Controls.Add(this.groupBox1);
            this.publicClientTabPage.Controls.Add(this.loginHint);
            this.publicClientTabPage.Controls.Add(this.label6);
            this.publicClientTabPage.Controls.Add(this.label5);
            this.publicClientTabPage.Controls.Add(this.overriddenAuthority);
            this.publicClientTabPage.Controls.Add(this.label4);
            this.publicClientTabPage.Controls.Add(this.label3);
            this.publicClientTabPage.Location = new System.Drawing.Point(4, 22);
            this.publicClientTabPage.Name = "publicClientTabPage";
            this.publicClientTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.publicClientTabPage.Size = new System.Drawing.Size(668, 788);
            this.publicClientTabPage.TabIndex = 0;
            this.publicClientTabPage.Text = "publicClientTabPage";
            this.publicClientTabPage.Click += new System.EventHandler(this.publicClientTabPage_Click);
            // 
            // IdTokenResult
            // 
            this.IdTokenResult.Location = new System.Drawing.Point(131, 586);
            this.IdTokenResult.Multiline = true;
            this.IdTokenResult.Name = "IdTokenResult";
            this.IdTokenResult.Size = new System.Drawing.Size(481, 40);
            this.IdTokenResult.TabIndex = 34;
            // 
            // accessTokenResult
            // 
            this.accessTokenResult.Location = new System.Drawing.Point(130, 417);
            this.accessTokenResult.Multiline = true;
            this.accessTokenResult.Name = "accessTokenResult";
            this.accessTokenResult.Size = new System.Drawing.Size(483, 92);
            this.accessTokenResult.TabIndex = 33;
            // 
            // label12
            // 
            this.label12.AutoSize = true;
            this.label12.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.875F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label12.Location = new System.Drawing.Point(11, 361);
            this.label12.Name = "label12";
            this.label12.Size = new System.Drawing.Size(101, 13);
            this.label12.TabIndex = 32;
            this.label12.Text = "Pii Logging Enabled";
            // 
            // PiiLoggingDisabled
            // 
            this.PiiLoggingDisabled.AutoSize = true;
            this.PiiLoggingDisabled.Checked = true;
            this.PiiLoggingDisabled.Location = new System.Drawing.Point(366, 361);
            this.PiiLoggingDisabled.Name = "PiiLoggingDisabled";
            this.PiiLoggingDisabled.Size = new System.Drawing.Size(66, 17);
            this.PiiLoggingDisabled.TabIndex = 31;
            this.PiiLoggingDisabled.TabStop = true;
            this.PiiLoggingDisabled.Text = "Disabled";
            this.PiiLoggingDisabled.UseVisualStyleBackColor = true;
            // 
            // PiiLoggingEnabled
            // 
            this.PiiLoggingEnabled.AutoSize = true;
            this.PiiLoggingEnabled.Location = new System.Drawing.Point(262, 361);
            this.PiiLoggingEnabled.Name = "PiiLoggingEnabled";
            this.PiiLoggingEnabled.Size = new System.Drawing.Size(64, 17);
            this.PiiLoggingEnabled.TabIndex = 30;
            this.PiiLoggingEnabled.Text = "Enabled";
            this.PiiLoggingEnabled.UseVisualStyleBackColor = true;
            // 
            // PiiLoggingLabel
            // 
            this.PiiLoggingLabel.AutoSize = true;
            this.PiiLoggingLabel.Location = new System.Drawing.Point(25, 716);
            this.PiiLoggingLabel.Name = "PiiLoggingLabel";
            this.PiiLoggingLabel.Size = new System.Drawing.Size(0, 13);
            this.PiiLoggingLabel.TabIndex = 29;
            // 
            // ScopeResult
            // 
            this.ScopeResult.FormattingEnabled = true;
            this.ScopeResult.Location = new System.Drawing.Point(130, 632);
            this.ScopeResult.Name = "ScopeResult";
            this.ScopeResult.Size = new System.Drawing.Size(150, 30);
            this.ScopeResult.TabIndex = 28;
            // 
            // Scope
            // 
            this.Scope.AutoSize = true;
            this.Scope.Location = new System.Drawing.Point(34, 632);
            this.Scope.Name = "Scope";
            this.Scope.Size = new System.Drawing.Size(38, 13);
            this.Scope.TabIndex = 27;
            this.Scope.Text = "Scope";
            // 
            // IdToken
            // 
            this.IdToken.AutoSize = true;
            this.IdToken.Location = new System.Drawing.Point(34, 592);
            this.IdToken.Name = "IdToken";
            this.IdToken.Size = new System.Drawing.Size(50, 13);
            this.IdToken.TabIndex = 25;
            this.IdToken.Text = "Id Token";
            // 
            // UserResult
            // 
            this.UserResult.AutoSize = true;
            this.UserResult.Location = new System.Drawing.Point(127, 568);
            this.UserResult.Name = "UserResult";
            this.UserResult.Size = new System.Drawing.Size(88, 13);
            this.UserResult.TabIndex = 24;
            this.UserResult.Text = "User Placeholder";
            // 
            // User
            // 
            this.User.AutoSize = true;
            this.User.Location = new System.Drawing.Point(34, 568);
            this.User.Name = "User";
            this.User.Size = new System.Drawing.Size(29, 13);
            this.User.TabIndex = 23;
            this.User.Text = "User";
            // 
            // TenantIdResult
            // 
            this.TenantIdResult.AutoSize = true;
            this.TenantIdResult.Location = new System.Drawing.Point(127, 542);
            this.TenantIdResult.Name = "TenantIdResult";
            this.TenantIdResult.Size = new System.Drawing.Size(112, 13);
            this.TenantIdResult.TabIndex = 22;
            this.TenantIdResult.Text = "Tenant Id Placeholder";
            // 
            // TenantId
            // 
            this.TenantId.AutoSize = true;
            this.TenantId.Location = new System.Drawing.Point(34, 542);
            this.TenantId.Name = "TenantId";
            this.TenantId.Size = new System.Drawing.Size(53, 13);
            this.TenantId.TabIndex = 21;
            this.TenantId.Text = "Tenant Id";
            // 
            // ExpiresOnResult
            // 
            this.ExpiresOnResult.AutoSize = true;
            this.ExpiresOnResult.Location = new System.Drawing.Point(127, 512);
            this.ExpiresOnResult.Name = "ExpiresOnResult";
            this.ExpiresOnResult.Size = new System.Drawing.Size(117, 13);
            this.ExpiresOnResult.TabIndex = 20;
            this.ExpiresOnResult.Text = "Expires On Placeholder";
            // 
            // ExpiresOn
            // 
            this.ExpiresOn.AutoSize = true;
            this.ExpiresOn.Location = new System.Drawing.Point(34, 512);
            this.ExpiresOn.Name = "ExpiresOn";
            this.ExpiresOn.Size = new System.Drawing.Size(58, 13);
            this.ExpiresOn.TabIndex = 19;
            this.ExpiresOn.Text = "Expires On";
            // 
            // AccessToken
            // 
            this.AccessToken.AutoSize = true;
            this.AccessToken.Location = new System.Drawing.Point(32, 420);
            this.AccessToken.Name = "AccessToken";
            this.AccessToken.Size = new System.Drawing.Size(76, 13);
            this.AccessToken.TabIndex = 17;
            this.AccessToken.Text = "Access Token";
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
            this.label9.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.875F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label9.Location = new System.Drawing.Point(8, 312);
            this.label9.Name = "label9";
            this.label9.Size = new System.Drawing.Size(43, 13);
            this.label9.TabIndex = 14;
            this.label9.Text = "Scopes";
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
            this.callResult.Location = new System.Drawing.Point(15, 403);
            this.callResult.Multiline = true;
            this.callResult.Name = "callResult";
            this.callResult.ReadOnly = true;
            this.callResult.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.callResult.Size = new System.Drawing.Size(645, 267);
            this.callResult.TabIndex = 13;
            // 
            // label8
            // 
            this.label8.AutoSize = true;
            this.label8.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.875F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label8.Location = new System.Drawing.Point(8, 172);
            this.label8.Name = "label8";
            this.label8.Size = new System.Drawing.Size(63, 13);
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
            this.label7.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.875F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label7.Location = new System.Drawing.Point(8, 266);
            this.label7.Name = "label7";
            this.label7.Size = new System.Drawing.Size(29, 13);
            this.label7.TabIndex = 11;
            this.label7.Text = "User";
            // 
            // acquireTokenSilent
            // 
            this.acquireTokenSilent.Location = new System.Drawing.Point(453, 683);
            this.acquireTokenSilent.Name = "acquireTokenSilent";
            this.acquireTokenSilent.Size = new System.Drawing.Size(164, 46);
            this.acquireTokenSilent.TabIndex = 10;
            this.acquireTokenSilent.Text = "Acquire Token Silent";
            this.acquireTokenSilent.UseVisualStyleBackColor = true;
            this.acquireTokenSilent.Click += new System.EventHandler(this.acquireTokenSilent_Click);
            // 
            // acquireTokenInteractive
            // 
            this.acquireTokenInteractive.Location = new System.Drawing.Point(35, 683);
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
            this.label6.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.875F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label6.Location = new System.Drawing.Point(8, 228);
            this.label6.Name = "label6";
            this.label6.Size = new System.Drawing.Size(55, 13);
            this.label6.TabIndex = 5;
            this.label6.Text = "Login Hint";
            // 
            // label5
            // 
            this.label5.AutoSize = true;
            this.label5.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.875F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label5.Location = new System.Drawing.Point(8, 109);
            this.label5.Name = "label5";
            this.label5.Size = new System.Drawing.Size(89, 13);
            this.label5.TabIndex = 4;
            this.label5.Text = "Validate Authority";
            // 
            // overriddenAuthority
            // 
            this.overriddenAuthority.Location = new System.Drawing.Point(256, 59);
            this.overriddenAuthority.Name = "overriddenAuthority";
            this.overriddenAuthority.Size = new System.Drawing.Size(352, 20);
            this.overriddenAuthority.TabIndex = 3;
            // 
            // label4
            // 
            this.label4.AutoSize = true;
            this.label4.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.875F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label4.Location = new System.Drawing.Point(8, 58);
            this.label4.Name = "label4";
            this.label4.Size = new System.Drawing.Size(146, 13);
            this.label4.TabIndex = 2;
            this.label4.Text = "Overridden Authority for 1 call";
            // 
            // label3
            // 
            this.label3.AutoSize = true;
            this.label3.Font = new System.Drawing.Font("Microsoft Sans Serif", 7.875F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label3.Location = new System.Drawing.Point(8, 19);
            this.label3.Name = "label3";
            this.label3.Size = new System.Drawing.Size(48, 13);
            this.label3.TabIndex = 0;
            this.label3.Text = "Authority";
            // 
            // settingsTabPage
            // 
            this.settingsTabPage.Controls.Add(this.extraQueryParams);
            this.settingsTabPage.Controls.Add(this.label11);
            this.settingsTabPage.Controls.Add(this.applySettings);
            this.settingsTabPage.Controls.Add(this.environmentQP);
            this.settingsTabPage.Controls.Add(this.label10);
            this.settingsTabPage.Location = new System.Drawing.Point(4, 22);
            this.settingsTabPage.Name = "settingsTabPage";
            this.settingsTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.settingsTabPage.Size = new System.Drawing.Size(668, 788);
            this.settingsTabPage.TabIndex = 1;
            this.settingsTabPage.Text = "settingsTabPage";
            this.settingsTabPage.UseVisualStyleBackColor = true;
            // 
            // label11
            // 
            this.label11.AutoSize = true;
            this.label11.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label11.Location = new System.Drawing.Point(10, 78);
            this.label11.Name = "label11";
            this.label11.Size = new System.Drawing.Size(178, 24);
            this.label11.TabIndex = 20;
            this.label11.Text = "Extra Query Params";
            // 
            // applySettings
            // 
            this.applySettings.Location = new System.Drawing.Point(437, 704);
            this.applySettings.Name = "applySettings";
            this.applySettings.Size = new System.Drawing.Size(140, 46);
            this.applySettings.TabIndex = 19;
            this.applySettings.Text = "Apply";
            this.applySettings.UseVisualStyleBackColor = true;
            this.applySettings.Click += new System.EventHandler(this.applySettings_Click);
            // 
            // label10
            // 
            this.label10.AutoSize = true;
            this.label10.Font = new System.Drawing.Font("Microsoft Sans Serif", 14F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.label10.Location = new System.Drawing.Point(10, 20);
            this.label10.Name = "label10";
            this.label10.Size = new System.Drawing.Size(149, 24);
            this.label10.TabIndex = 17;
            this.label10.Text = "Environment QP";
            // 
            // cacheTabPage
            // 
            this.cacheTabPage.Controls.Add(this.ExpiresOnResultInCache);
            this.cacheTabPage.Controls.Add(this.ExpiresOnInCache);
            this.cacheTabPage.Controls.Add(this.UserResultInCache);
            this.cacheTabPage.Controls.Add(this.UserInCache);
            this.cacheTabPage.Controls.Add(this.AccessTokenResultInCache);
            this.cacheTabPage.Controls.Add(this.ExpireAccessTokenBtn);
            this.cacheTabPage.Location = new System.Drawing.Point(4, 22);
            this.cacheTabPage.Name = "cacheTabPage";
            this.cacheTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.cacheTabPage.Size = new System.Drawing.Size(668, 788);
            this.cacheTabPage.TabIndex = 2;
            this.cacheTabPage.Text = "cacheTabPage";
            this.cacheTabPage.UseVisualStyleBackColor = true;
            // 
            // ExpiresOnResultInCache
            // 
            this.ExpiresOnResultInCache.AutoSize = true;
            this.ExpiresOnResultInCache.Location = new System.Drawing.Point(276, 248);
            this.ExpiresOnResultInCache.Name = "ExpiresOnResultInCache";
            this.ExpiresOnResultInCache.Size = new System.Drawing.Size(114, 13);
            this.ExpiresOnResultInCache.TabIndex = 5;
            this.ExpiresOnResultInCache.Text = "Expires on placeholder";
            // 
            // ExpiresOnInCache
            // 
            this.ExpiresOnInCache.AutoSize = true;
            this.ExpiresOnInCache.Location = new System.Drawing.Point(212, 248);
            this.ExpiresOnInCache.Name = "ExpiresOnInCache";
            this.ExpiresOnInCache.Size = new System.Drawing.Size(58, 13);
            this.ExpiresOnInCache.TabIndex = 4;
            this.ExpiresOnInCache.Text = "Expires On";
            // 
            // UserResultInCache
            // 
            this.UserResultInCache.AutoSize = true;
            this.UserResultInCache.Location = new System.Drawing.Point(276, 222);
            this.UserResultInCache.Name = "UserResultInCache";
            this.UserResultInCache.Size = new System.Drawing.Size(88, 13);
            this.UserResultInCache.TabIndex = 3;
            this.UserResultInCache.Text = "User Placeholder";
            // 
            // UserInCache
            // 
            this.UserInCache.AutoSize = true;
            this.UserInCache.Location = new System.Drawing.Point(212, 222);
            this.UserInCache.Name = "UserInCache";
            this.UserInCache.Size = new System.Drawing.Size(29, 13);
            this.UserInCache.TabIndex = 2;
            this.UserInCache.Text = "User";
            // 
            // AccessTokenResultInCache
            // 
            this.AccessTokenResultInCache.Location = new System.Drawing.Point(215, 20);
            this.AccessTokenResultInCache.Multiline = true;
            this.AccessTokenResultInCache.Name = "AccessTokenResultInCache";
            this.AccessTokenResultInCache.Size = new System.Drawing.Size(424, 188);
            this.AccessTokenResultInCache.TabIndex = 1;
            // 
            // ExpireAccessTokenBtn
            // 
            this.ExpireAccessTokenBtn.Location = new System.Drawing.Point(23, 30);
            this.ExpireAccessTokenBtn.Name = "ExpireAccessTokenBtn";
            this.ExpireAccessTokenBtn.Size = new System.Drawing.Size(154, 54);
            this.ExpireAccessTokenBtn.TabIndex = 0;
            this.ExpireAccessTokenBtn.Text = "Expire Access Token";
            this.ExpireAccessTokenBtn.UseVisualStyleBackColor = true;
            this.ExpireAccessTokenBtn.Click += new System.EventHandler(this.ExpireAccessTokenBtn_Click);
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
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(143, 349);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(352, 13);
            this.label1.TabIndex = 1;
            this.label1.Text = "========================= PII Logs =========================";
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
            // confidentialClientTabPage
            // 
            this.confidentialClientTabPage.Controls.Add(this.ConfClientIdTokenResult);
            this.confidentialClientTabPage.Controls.Add(this.confClientAcquireTokenSilentBtn);
            this.confidentialClientTabPage.Controls.Add(this.confClientAcquireTokenBtn);
            this.confidentialClientTabPage.Controls.Add(this.confClientPiiEnabledButton);
            this.confidentialClientTabPage.Controls.Add(this.confClientPiiDisabledButton);
            this.confidentialClientTabPage.Controls.Add(this.confClientPiiEnabledLabel);
            this.confidentialClientTabPage.Controls.Add(this.confClientScopesResult);
            this.confidentialClientTabPage.Controls.Add(this.conClientScopesLabel);
            this.confidentialClientTabPage.Controls.Add(this.confClientIdTokenLabel);
            this.confidentialClientTabPage.Controls.Add(this.confClientUserResult);
            this.confidentialClientTabPage.Controls.Add(this.conClientUserLabel);
            this.confidentialClientTabPage.Controls.Add(this.confClientTenantIdResult);
            this.confidentialClientTabPage.Controls.Add(this.confClientTenantIdLabel);
            this.confidentialClientTabPage.Controls.Add(this.confClientExpiresOnResult);
            this.confidentialClientTabPage.Controls.Add(this.confClientExpiresOnLabel);
            this.confidentialClientTabPage.Controls.Add(this.confClientAccessTokenResult);
            this.confidentialClientTabPage.Controls.Add(this.confClientAccessTokenLabel);
            this.confidentialClientTabPage.Controls.Add(this.callResultConfClient);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientScopesBox);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientScopesLabel);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientUserBox);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientUserLabel);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientLoginHintBox);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientLoginHintLabel);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientNeverButton);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientConsentButton);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientForceLoginButton);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientSelectAccountButton);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientUiBehaviorLabel);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientValidateAuthorityDisabled);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientValidateAuthorityEnabled);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientValidateAuthorityLabel);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientOverrideAuthority);
            this.confidentialClientTabPage.Controls.Add(this.label13);
            this.confidentialClientTabPage.Controls.Add(this.ConfClientAuthority);
            this.confidentialClientTabPage.Controls.Add(this.CcAuthorityLabel);
            this.confidentialClientTabPage.Location = new System.Drawing.Point(4, 22);
            this.confidentialClientTabPage.Name = "confidentialClientTabPage";
            this.confidentialClientTabPage.Padding = new System.Windows.Forms.Padding(3);
            this.confidentialClientTabPage.Size = new System.Drawing.Size(668, 788);
            this.confidentialClientTabPage.TabIndex = 4;
            this.confidentialClientTabPage.Text = "confidentialClientTabPage";
            this.confidentialClientTabPage.UseVisualStyleBackColor = true;
            // 
            // confClientAcquireTokenSilentBtn
            // 
            this.confClientAcquireTokenSilentBtn.Location = new System.Drawing.Point(451, 700);
            this.confClientAcquireTokenSilentBtn.Name = "confClientAcquireTokenSilentBtn";
            this.confClientAcquireTokenSilentBtn.Size = new System.Drawing.Size(160, 58);
            this.confClientAcquireTokenSilentBtn.TabIndex = 35;
            this.confClientAcquireTokenSilentBtn.Text = "Acquire Token Silent";
            this.confClientAcquireTokenSilentBtn.UseVisualStyleBackColor = true;
            // 
            // confClientAcquireTokenBtn
            // 
            this.confClientAcquireTokenBtn.Location = new System.Drawing.Point(43, 700);
            this.confClientAcquireTokenBtn.Name = "confClientAcquireTokenBtn";
            this.confClientAcquireTokenBtn.Size = new System.Drawing.Size(154, 50);
            this.confClientAcquireTokenBtn.TabIndex = 34;
            this.confClientAcquireTokenBtn.Text = "Acquire Token";
            this.confClientAcquireTokenBtn.UseVisualStyleBackColor = true;
            // 
            // confClientPiiEnabledButton
            // 
            this.confClientPiiEnabledButton.AutoSize = true;
            this.confClientPiiEnabledButton.Location = new System.Drawing.Point(260, 301);
            this.confClientPiiEnabledButton.Name = "confClientPiiEnabledButton";
            this.confClientPiiEnabledButton.Size = new System.Drawing.Size(64, 17);
            this.confClientPiiEnabledButton.TabIndex = 33;
            this.confClientPiiEnabledButton.TabStop = true;
            this.confClientPiiEnabledButton.Text = "Enabled";
            this.confClientPiiEnabledButton.UseVisualStyleBackColor = true;
            // 
            // confClientPiiDisabledButton
            // 
            this.confClientPiiDisabledButton.AutoSize = true;
            this.confClientPiiDisabledButton.Checked = true;
            this.confClientPiiDisabledButton.Location = new System.Drawing.Point(175, 302);
            this.confClientPiiDisabledButton.Name = "confClientPiiDisabledButton";
            this.confClientPiiDisabledButton.Size = new System.Drawing.Size(66, 17);
            this.confClientPiiDisabledButton.TabIndex = 32;
            this.confClientPiiDisabledButton.TabStop = true;
            this.confClientPiiDisabledButton.Text = "Disabled";
            this.confClientPiiDisabledButton.UseVisualStyleBackColor = true;
            // 
            // confClientPiiEnabledLabel
            // 
            this.confClientPiiEnabledLabel.AutoSize = true;
            this.confClientPiiEnabledLabel.Location = new System.Drawing.Point(27, 308);
            this.confClientPiiEnabledLabel.Name = "confClientPiiEnabledLabel";
            this.confClientPiiEnabledLabel.Size = new System.Drawing.Size(101, 13);
            this.confClientPiiEnabledLabel.TabIndex = 31;
            this.confClientPiiEnabledLabel.Text = "Pii Logging Enabled";
            // 
            // confClientScopesResult
            // 
            this.confClientScopesResult.FormattingEnabled = true;
            this.confClientScopesResult.Location = new System.Drawing.Point(144, 624);
            this.confClientScopesResult.Name = "confClientScopesResult";
            this.confClientScopesResult.Size = new System.Drawing.Size(477, 56);
            this.confClientScopesResult.TabIndex = 30;
            // 
            // conClientScopesLabel
            // 
            this.conClientScopesLabel.AutoSize = true;
            this.conClientScopesLabel.Location = new System.Drawing.Point(39, 627);
            this.conClientScopesLabel.Name = "conClientScopesLabel";
            this.conClientScopesLabel.Size = new System.Drawing.Size(43, 13);
            this.conClientScopesLabel.TabIndex = 29;
            this.conClientScopesLabel.Text = "Scopes";
            // 
            // confClientIdTokenLabel
            // 
            this.confClientIdTokenLabel.AutoSize = true;
            this.confClientIdTokenLabel.Location = new System.Drawing.Point(39, 590);
            this.confClientIdTokenLabel.Name = "confClientIdTokenLabel";
            this.confClientIdTokenLabel.Size = new System.Drawing.Size(50, 13);
            this.confClientIdTokenLabel.TabIndex = 27;
            this.confClientIdTokenLabel.Text = "Id Token";
            // 
            // confClientUserResult
            // 
            this.confClientUserResult.AutoSize = true;
            this.confClientUserResult.Location = new System.Drawing.Point(144, 564);
            this.confClientUserResult.Name = "confClientUserResult";
            this.confClientUserResult.Size = new System.Drawing.Size(88, 13);
            this.confClientUserResult.TabIndex = 26;
            this.confClientUserResult.Text = "User Placeholder";
            // 
            // conClientUserLabel
            // 
            this.conClientUserLabel.AutoSize = true;
            this.conClientUserLabel.Location = new System.Drawing.Point(39, 564);
            this.conClientUserLabel.Name = "conClientUserLabel";
            this.conClientUserLabel.Size = new System.Drawing.Size(29, 13);
            this.conClientUserLabel.TabIndex = 25;
            this.conClientUserLabel.Text = "User";
            // 
            // confClientTenantIdResult
            // 
            this.confClientTenantIdResult.AutoSize = true;
            this.confClientTenantIdResult.Location = new System.Drawing.Point(141, 532);
            this.confClientTenantIdResult.Name = "confClientTenantIdResult";
            this.confClientTenantIdResult.Size = new System.Drawing.Size(112, 13);
            this.confClientTenantIdResult.TabIndex = 24;
            this.confClientTenantIdResult.Text = "Tenant Id Placeholder";
            // 
            // confClientTenantIdLabel
            // 
            this.confClientTenantIdLabel.AutoSize = true;
            this.confClientTenantIdLabel.Location = new System.Drawing.Point(39, 532);
            this.confClientTenantIdLabel.Name = "confClientTenantIdLabel";
            this.confClientTenantIdLabel.Size = new System.Drawing.Size(53, 13);
            this.confClientTenantIdLabel.TabIndex = 23;
            this.confClientTenantIdLabel.Text = "Tenant Id";
            // 
            // confClientExpiresOnResult
            // 
            this.confClientExpiresOnResult.AutoSize = true;
            this.confClientExpiresOnResult.Location = new System.Drawing.Point(142, 504);
            this.confClientExpiresOnResult.Name = "confClientExpiresOnResult";
            this.confClientExpiresOnResult.Size = new System.Drawing.Size(117, 13);
            this.confClientExpiresOnResult.TabIndex = 22;
            this.confClientExpiresOnResult.Text = "Expires On Placeholder";
            // 
            // confClientExpiresOnLabel
            // 
            this.confClientExpiresOnLabel.AutoSize = true;
            this.confClientExpiresOnLabel.Location = new System.Drawing.Point(39, 504);
            this.confClientExpiresOnLabel.Name = "confClientExpiresOnLabel";
            this.confClientExpiresOnLabel.Size = new System.Drawing.Size(58, 13);
            this.confClientExpiresOnLabel.TabIndex = 21;
            this.confClientExpiresOnLabel.Text = "Expires On";
            // 
            // confClientAccessTokenResult
            // 
            this.confClientAccessTokenResult.Location = new System.Drawing.Point(145, 362);
            this.confClientAccessTokenResult.Multiline = true;
            this.confClientAccessTokenResult.Name = "confClientAccessTokenResult";
            this.confClientAccessTokenResult.Size = new System.Drawing.Size(480, 139);
            this.confClientAccessTokenResult.TabIndex = 20;
            // 
            // confClientAccessTokenLabel
            // 
            this.confClientAccessTokenLabel.AutoSize = true;
            this.confClientAccessTokenLabel.Location = new System.Drawing.Point(39, 358);
            this.confClientAccessTokenLabel.Name = "confClientAccessTokenLabel";
            this.confClientAccessTokenLabel.Size = new System.Drawing.Size(76, 13);
            this.confClientAccessTokenLabel.TabIndex = 19;
            this.confClientAccessTokenLabel.Text = "Access Token";
            // 
            // callResultConfClient
            // 
            this.callResultConfClient.Location = new System.Drawing.Point(25, 348);
            this.callResultConfClient.Multiline = true;
            this.callResultConfClient.Name = "callResultConfClient";
            this.callResultConfClient.Size = new System.Drawing.Size(615, 344);
            this.callResultConfClient.TabIndex = 18;
            // 
            // ConfClientScopesBox
            // 
            this.ConfClientScopesBox.Location = new System.Drawing.Point(175, 236);
            this.ConfClientScopesBox.Name = "ConfClientScopesBox";
            this.ConfClientScopesBox.Size = new System.Drawing.Size(464, 50);
            this.ConfClientScopesBox.TabIndex = 17;
            this.ConfClientScopesBox.UseCompatibleStateImageBehavior = false;
            // 
            // ConfClientScopesLabel
            // 
            this.ConfClientScopesLabel.AutoSize = true;
            this.ConfClientScopesLabel.Location = new System.Drawing.Point(23, 248);
            this.ConfClientScopesLabel.Name = "ConfClientScopesLabel";
            this.ConfClientScopesLabel.Size = new System.Drawing.Size(43, 13);
            this.ConfClientScopesLabel.TabIndex = 16;
            this.ConfClientScopesLabel.Text = "Scopes";
            // 
            // ConfClientUserBox
            // 
            this.ConfClientUserBox.Location = new System.Drawing.Point(175, 197);
            this.ConfClientUserBox.Name = "ConfClientUserBox";
            this.ConfClientUserBox.Size = new System.Drawing.Size(467, 20);
            this.ConfClientUserBox.TabIndex = 15;
            // 
            // ConfClientUserLabel
            // 
            this.ConfClientUserLabel.AutoSize = true;
            this.ConfClientUserLabel.Location = new System.Drawing.Point(26, 200);
            this.ConfClientUserLabel.Name = "ConfClientUserLabel";
            this.ConfClientUserLabel.Size = new System.Drawing.Size(29, 13);
            this.ConfClientUserLabel.TabIndex = 14;
            this.ConfClientUserLabel.Text = "User";
            // 
            // ConfClientLoginHintBox
            // 
            this.ConfClientLoginHintBox.Location = new System.Drawing.Point(175, 152);
            this.ConfClientLoginHintBox.Name = "ConfClientLoginHintBox";
            this.ConfClientLoginHintBox.Size = new System.Drawing.Size(474, 20);
            this.ConfClientLoginHintBox.TabIndex = 13;
            // 
            // ConfClientLoginHintLabel
            // 
            this.ConfClientLoginHintLabel.AutoSize = true;
            this.ConfClientLoginHintLabel.Location = new System.Drawing.Point(26, 155);
            this.ConfClientLoginHintLabel.Name = "ConfClientLoginHintLabel";
            this.ConfClientLoginHintLabel.Size = new System.Drawing.Size(55, 13);
            this.ConfClientLoginHintLabel.TabIndex = 12;
            this.ConfClientLoginHintLabel.Text = "Login Hint";
            // 
            // ConfClientNeverButton
            // 
            this.ConfClientNeverButton.AutoSize = true;
            this.ConfClientNeverButton.Location = new System.Drawing.Point(501, 115);
            this.ConfClientNeverButton.Name = "ConfClientNeverButton";
            this.ConfClientNeverButton.Size = new System.Drawing.Size(54, 17);
            this.ConfClientNeverButton.TabIndex = 11;
            this.ConfClientNeverButton.Text = "Never";
            this.ConfClientNeverButton.UseVisualStyleBackColor = true;
            // 
            // ConfClientConsentButton
            // 
            this.ConfClientConsentButton.AutoSize = true;
            this.ConfClientConsentButton.Location = new System.Drawing.Point(407, 115);
            this.ConfClientConsentButton.Name = "ConfClientConsentButton";
            this.ConfClientConsentButton.Size = new System.Drawing.Size(64, 17);
            this.ConfClientConsentButton.TabIndex = 10;
            this.ConfClientConsentButton.Text = "Consent";
            this.ConfClientConsentButton.UseVisualStyleBackColor = true;
            // 
            // ConfClientForceLoginButton
            // 
            this.ConfClientForceLoginButton.AutoSize = true;
            this.ConfClientForceLoginButton.Location = new System.Drawing.Point(296, 115);
            this.ConfClientForceLoginButton.Name = "ConfClientForceLoginButton";
            this.ConfClientForceLoginButton.Size = new System.Drawing.Size(81, 17);
            this.ConfClientForceLoginButton.TabIndex = 9;
            this.ConfClientForceLoginButton.Text = "Force Login";
            this.ConfClientForceLoginButton.UseVisualStyleBackColor = true;
            // 
            // ConfClientSelectAccountButton
            // 
            this.ConfClientSelectAccountButton.AutoSize = true;
            this.ConfClientSelectAccountButton.Location = new System.Drawing.Point(176, 115);
            this.ConfClientSelectAccountButton.Name = "ConfClientSelectAccountButton";
            this.ConfClientSelectAccountButton.Size = new System.Drawing.Size(98, 17);
            this.ConfClientSelectAccountButton.TabIndex = 8;
            this.ConfClientSelectAccountButton.Text = "Select Account";
            this.ConfClientSelectAccountButton.UseVisualStyleBackColor = true;
            // 
            // ConfClientUiBehaviorLabel
            // 
            this.ConfClientUiBehaviorLabel.AutoSize = true;
            this.ConfClientUiBehaviorLabel.Location = new System.Drawing.Point(26, 122);
            this.ConfClientUiBehaviorLabel.Name = "ConfClientUiBehaviorLabel";
            this.ConfClientUiBehaviorLabel.Size = new System.Drawing.Size(63, 13);
            this.ConfClientUiBehaviorLabel.TabIndex = 7;
            this.ConfClientUiBehaviorLabel.Text = "UI Behavior";
            // 
            // ConfClientValidateAuthorityDisabled
            // 
            this.ConfClientValidateAuthorityDisabled.AutoSize = true;
            this.ConfClientValidateAuthorityDisabled.Location = new System.Drawing.Point(281, 73);
            this.ConfClientValidateAuthorityDisabled.Name = "ConfClientValidateAuthorityDisabled";
            this.ConfClientValidateAuthorityDisabled.Size = new System.Drawing.Size(66, 17);
            this.ConfClientValidateAuthorityDisabled.TabIndex = 6;
            this.ConfClientValidateAuthorityDisabled.Text = "Disabled";
            this.ConfClientValidateAuthorityDisabled.UseVisualStyleBackColor = true;
            // 
            // ConfClientValidateAuthorityEnabled
            // 
            this.ConfClientValidateAuthorityEnabled.AutoSize = true;
            this.ConfClientValidateAuthorityEnabled.Location = new System.Drawing.Point(176, 73);
            this.ConfClientValidateAuthorityEnabled.Name = "ConfClientValidateAuthorityEnabled";
            this.ConfClientValidateAuthorityEnabled.Size = new System.Drawing.Size(64, 17);
            this.ConfClientValidateAuthorityEnabled.TabIndex = 5;
            this.ConfClientValidateAuthorityEnabled.Text = "Enabled";
            this.ConfClientValidateAuthorityEnabled.UseVisualStyleBackColor = true;
            // 
            // ConfClientValidateAuthorityLabel
            // 
            this.ConfClientValidateAuthorityLabel.AutoSize = true;
            this.ConfClientValidateAuthorityLabel.Location = new System.Drawing.Point(23, 80);
            this.ConfClientValidateAuthorityLabel.Name = "ConfClientValidateAuthorityLabel";
            this.ConfClientValidateAuthorityLabel.Size = new System.Drawing.Size(89, 13);
            this.ConfClientValidateAuthorityLabel.TabIndex = 4;
            this.ConfClientValidateAuthorityLabel.Text = "Validate Authority";
            // 
            // ConfClientOverrideAuthority
            // 
            this.ConfClientOverrideAuthority.Location = new System.Drawing.Point(187, 41);
            this.ConfClientOverrideAuthority.Name = "ConfClientOverrideAuthority";
            this.ConfClientOverrideAuthority.Size = new System.Drawing.Size(308, 20);
            this.ConfClientOverrideAuthority.TabIndex = 3;
            // 
            // label13
            // 
            this.label13.AutoSize = true;
            this.label13.Location = new System.Drawing.Point(23, 48);
            this.label13.Name = "label13";
            this.label13.Size = new System.Drawing.Size(147, 13);
            this.label13.TabIndex = 2;
            this.label13.Text = "Overridden Authority for 1 Call";
            // 
            // ConfClientAuthority
            // 
            this.ConfClientAuthority.AutoSize = true;
            this.ConfClientAuthority.Location = new System.Drawing.Point(184, 20);
            this.ConfClientAuthority.Name = "ConfClientAuthority";
            this.ConfClientAuthority.Size = new System.Drawing.Size(206, 13);
            this.ConfClientAuthority.TabIndex = 1;
            this.ConfClientAuthority.Text = "https://login.microsoftonline.com/common";
            // 
            // CcAuthorityLabel
            // 
            this.CcAuthorityLabel.AutoSize = true;
            this.CcAuthorityLabel.Location = new System.Drawing.Point(23, 20);
            this.CcAuthorityLabel.Name = "CcAuthorityLabel";
            this.CcAuthorityLabel.Size = new System.Drawing.Size(48, 13);
            this.CcAuthorityLabel.TabIndex = 0;
            this.CcAuthorityLabel.Text = "Authority";
            // 
            // publicClient
            // 
            this.publicClient.Location = new System.Drawing.Point(1, 817);
            this.publicClient.Name = "publicClient";
            this.publicClient.Size = new System.Drawing.Size(116, 45);
            this.publicClient.TabIndex = 1;
            this.publicClient.Text = "Public Client";
            this.publicClient.UseVisualStyleBackColor = true;
            this.publicClient.Click += new System.EventHandler(this.acquire_Click);
            // 
            // settings
            // 
            this.settings.Location = new System.Drawing.Point(303, 817);
            this.settings.Name = "settings";
            this.settings.Size = new System.Drawing.Size(96, 45);
            this.settings.TabIndex = 2;
            this.settings.Text = "Settings";
            this.settings.UseVisualStyleBackColor = true;
            this.settings.Click += new System.EventHandler(this.settings_Click);
            // 
            // cache
            // 
            this.cache.Location = new System.Drawing.Point(434, 817);
            this.cache.Name = "cache";
            this.cache.Size = new System.Drawing.Size(110, 45);
            this.cache.TabIndex = 3;
            this.cache.Text = "Cache";
            this.cache.UseVisualStyleBackColor = true;
            this.cache.Click += new System.EventHandler(this.cache_Click);
            // 
            // logs
            // 
            this.logs.Location = new System.Drawing.Point(581, 817);
            this.logs.Name = "logs";
            this.logs.Size = new System.Drawing.Size(92, 45);
            this.logs.TabIndex = 4;
            this.logs.Text = "Logs";
            this.logs.UseVisualStyleBackColor = true;
            this.logs.Click += new System.EventHandler(this.logs_Click);
            // 
            // confidentialClient
            // 
            this.confidentialClient.Location = new System.Drawing.Point(147, 817);
            this.confidentialClient.Name = "confidentialClient";
            this.confidentialClient.Size = new System.Drawing.Size(115, 45);
            this.confidentialClient.TabIndex = 5;
            this.confidentialClient.Text = "Confidential Client";
            this.confidentialClient.UseVisualStyleBackColor = true;
            this.confidentialClient.Click += new System.EventHandler(this.confidentialClient_Click);
            // 
            // ConfClientIdTokenResult
            // 
            this.ConfClientIdTokenResult.Location = new System.Drawing.Point(143, 589);
            this.ConfClientIdTokenResult.Multiline = true;
            this.ConfClientIdTokenResult.Name = "ConfClientIdTokenResult";
            this.ConfClientIdTokenResult.Size = new System.Drawing.Size(481, 23);
            this.ConfClientIdTokenResult.TabIndex = 36;
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(674, 863);
            this.Controls.Add(this.confidentialClient);
            this.Controls.Add(this.logs);
            this.Controls.Add(this.cache);
            this.Controls.Add(this.settings);
            this.Controls.Add(this.publicClient);
            this.Controls.Add(this.tabControl1);
            this.MaximizeBox = false;
            this.Name = "MainForm";
            this.Text = "Dev Utility Test App";
            this.tabControl1.ResumeLayout(false);
            this.publicClientTabPage.ResumeLayout(false);
            this.publicClientTabPage.PerformLayout();
            this.groupBox2.ResumeLayout(false);
            this.groupBox2.PerformLayout();
            this.groupBox1.ResumeLayout(false);
            this.groupBox1.PerformLayout();
            this.settingsTabPage.ResumeLayout(false);
            this.settingsTabPage.PerformLayout();
            this.cacheTabPage.ResumeLayout(false);
            this.cacheTabPage.PerformLayout();
            this.logsTabPage.ResumeLayout(false);
            this.logsTabPage.PerformLayout();
            this.confidentialClientTabPage.ResumeLayout(false);
            this.confidentialClientTabPage.PerformLayout();
            this.ResumeLayout(false);

        }

        #endregion
        private System.Windows.Forms.TabControl tabControl1;
        private System.Windows.Forms.TabPage publicClientTabPage;
        private System.Windows.Forms.TabPage settingsTabPage;
        private System.Windows.Forms.Button publicClient;
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
        private System.Windows.Forms.Label label4;
        private System.Windows.Forms.TextBox overriddenAuthority;
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
        private System.Windows.Forms.Label label10;
        private System.Windows.Forms.Button applySettings;
        private System.Windows.Forms.Label label11;
        private System.Windows.Forms.Button confidentialClient;
        private System.Windows.Forms.TabPage confidentialClientTabPage;
        private System.Windows.Forms.TextBox authority;
        private System.Windows.Forms.TextBox extraQueryParams;
        private System.Windows.Forms.TextBox environmentQP;
        private System.Windows.Forms.Label AccessToken;
        private System.Windows.Forms.Label Scope;
        private System.Windows.Forms.Label IdToken;
        private System.Windows.Forms.Label UserResult;
        private System.Windows.Forms.Label User;
        private System.Windows.Forms.Label TenantIdResult;
        private System.Windows.Forms.Label TenantId;
        private System.Windows.Forms.Label ExpiresOnResult;
        private System.Windows.Forms.Label ExpiresOn;
        private System.Windows.Forms.ListBox ScopeResult;
        private System.Windows.Forms.Button ExpireAccessTokenBtn;
        private System.Windows.Forms.TextBox AccessTokenResultInCache;
        private System.Windows.Forms.Label ExpiresOnResultInCache;
        private System.Windows.Forms.Label ExpiresOnInCache;
        private System.Windows.Forms.Label UserResultInCache;
        private System.Windows.Forms.Label UserInCache;
        private System.Windows.Forms.RadioButton PiiLoggingDisabled;
        private System.Windows.Forms.RadioButton PiiLoggingEnabled;
        private System.Windows.Forms.Label PiiLoggingLabel;
        private System.Windows.Forms.Label label12;
        private System.Windows.Forms.RadioButton ConfClientValidateAuthorityDisabled;
        private System.Windows.Forms.RadioButton ConfClientValidateAuthorityEnabled;
        private System.Windows.Forms.Label ConfClientValidateAuthorityLabel;
        private System.Windows.Forms.TextBox ConfClientOverrideAuthority;
        private System.Windows.Forms.Label label13;
        private System.Windows.Forms.Label ConfClientAuthority;
        private System.Windows.Forms.Label CcAuthorityLabel;
        private System.Windows.Forms.ListView ConfClientScopesBox;
        private System.Windows.Forms.Label ConfClientScopesLabel;
        private System.Windows.Forms.TextBox ConfClientUserBox;
        private System.Windows.Forms.Label ConfClientUserLabel;
        private System.Windows.Forms.TextBox ConfClientLoginHintBox;
        private System.Windows.Forms.Label ConfClientLoginHintLabel;
        private System.Windows.Forms.RadioButton ConfClientNeverButton;
        private System.Windows.Forms.RadioButton ConfClientConsentButton;
        private System.Windows.Forms.RadioButton ConfClientForceLoginButton;
        private System.Windows.Forms.RadioButton ConfClientSelectAccountButton;
        private System.Windows.Forms.Label ConfClientUiBehaviorLabel;
        private System.Windows.Forms.Label confClientExpiresOnLabel;
        private System.Windows.Forms.TextBox confClientAccessTokenResult;
        private System.Windows.Forms.Label confClientAccessTokenLabel;
        private System.Windows.Forms.TextBox callResultConfClient;
        private System.Windows.Forms.ListBox confClientScopesResult;
        private System.Windows.Forms.Label conClientScopesLabel;
        private System.Windows.Forms.Label confClientIdTokenLabel;
        private System.Windows.Forms.Label confClientUserResult;
        private System.Windows.Forms.Label conClientUserLabel;
        private System.Windows.Forms.Label confClientTenantIdResult;
        private System.Windows.Forms.Label confClientTenantIdLabel;
        private System.Windows.Forms.Label confClientExpiresOnResult;
        private System.Windows.Forms.Button confClientAcquireTokenSilentBtn;
        private System.Windows.Forms.Button confClientAcquireTokenBtn;
        private System.Windows.Forms.RadioButton confClientPiiEnabledButton;
        private System.Windows.Forms.RadioButton confClientPiiDisabledButton;
        private System.Windows.Forms.Label confClientPiiEnabledLabel;
        private System.Windows.Forms.TextBox accessTokenResult;
        private System.Windows.Forms.TextBox IdTokenResult;
        private System.Windows.Forms.TextBox ConfClientIdTokenResult;
    }
}

