IF OBJECT_ID(N'[__EFMigrationsHistory]') IS NULL
BEGIN
    CREATE TABLE [__EFMigrationsHistory] (
        [MigrationId] nvarchar(150) NOT NULL,
        [ProductVersion] nvarchar(32) NOT NULL,
        CONSTRAINT [PK___EFMigrationsHistory] PRIMARY KEY ([MigrationId])
    );
END;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [AspNetRoles] (
        [Id] nvarchar(450) NOT NULL,
        [Name] nvarchar(256) NULL,
        [NormalizedName] nvarchar(256) NULL,
        [ConcurrencyStamp] nvarchar(max) NULL,
        CONSTRAINT [PK_AspNetRoles] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [AspNetUsers] (
        [Id] nvarchar(450) NOT NULL,
        [FullName] nvarchar(max) NOT NULL,
        [CreatedAt] datetime2 NOT NULL,
        [IsActive] bit NOT NULL,
        [UserName] nvarchar(256) NULL,
        [NormalizedUserName] nvarchar(256) NULL,
        [Email] nvarchar(256) NULL,
        [NormalizedEmail] nvarchar(256) NULL,
        [EmailConfirmed] bit NOT NULL,
        [PasswordHash] nvarchar(max) NULL,
        [SecurityStamp] nvarchar(max) NULL,
        [ConcurrencyStamp] nvarchar(max) NULL,
        [PhoneNumber] nvarchar(max) NULL,
        [PhoneNumberConfirmed] bit NOT NULL,
        [TwoFactorEnabled] bit NOT NULL,
        [LockoutEnd] datetimeoffset NULL,
        [LockoutEnabled] bit NOT NULL,
        [AccessFailedCount] int NOT NULL,
        CONSTRAINT [PK_AspNetUsers] PRIMARY KEY ([Id])
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [AspNetRoleClaims] (
        [Id] int NOT NULL IDENTITY,
        [RoleId] nvarchar(450) NOT NULL,
        [ClaimType] nvarchar(max) NULL,
        [ClaimValue] nvarchar(max) NULL,
        CONSTRAINT [PK_AspNetRoleClaims] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_AspNetRoleClaims_AspNetRoles_RoleId] FOREIGN KEY ([RoleId]) REFERENCES [AspNetRoles] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [AspNetUserClaims] (
        [Id] int NOT NULL IDENTITY,
        [UserId] nvarchar(450) NOT NULL,
        [ClaimType] nvarchar(max) NULL,
        [ClaimValue] nvarchar(max) NULL,
        CONSTRAINT [PK_AspNetUserClaims] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_AspNetUserClaims_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [AspNetUserLogins] (
        [LoginProvider] nvarchar(450) NOT NULL,
        [ProviderKey] nvarchar(450) NOT NULL,
        [ProviderDisplayName] nvarchar(max) NULL,
        [UserId] nvarchar(450) NOT NULL,
        CONSTRAINT [PK_AspNetUserLogins] PRIMARY KEY ([LoginProvider], [ProviderKey]),
        CONSTRAINT [FK_AspNetUserLogins_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [AspNetUserRoles] (
        [UserId] nvarchar(450) NOT NULL,
        [RoleId] nvarchar(450) NOT NULL,
        CONSTRAINT [PK_AspNetUserRoles] PRIMARY KEY ([UserId], [RoleId]),
        CONSTRAINT [FK_AspNetUserRoles_AspNetRoles_RoleId] FOREIGN KEY ([RoleId]) REFERENCES [AspNetRoles] ([Id]) ON DELETE CASCADE,
        CONSTRAINT [FK_AspNetUserRoles_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [AspNetUserTokens] (
        [UserId] nvarchar(450) NOT NULL,
        [LoginProvider] nvarchar(450) NOT NULL,
        [Name] nvarchar(450) NOT NULL,
        [Value] nvarchar(max) NULL,
        CONSTRAINT [PK_AspNetUserTokens] PRIMARY KEY ([UserId], [LoginProvider], [Name]),
        CONSTRAINT [FK_AspNetUserTokens_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [AuditLogs] (
        [Id] int NOT NULL IDENTITY,
        [UserId] nvarchar(450) NULL,
        [Action] nvarchar(100) NOT NULL,
        [Details] nvarchar(1000) NOT NULL,
        [IpAddress] nvarchar(45) NOT NULL,
        [Timestamp] datetime2 NOT NULL,
        CONSTRAINT [PK_AuditLogs] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_AuditLogs_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE SET NULL
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [ScanTargets] (
        [Id] int NOT NULL IDENTITY,
        [TargetUrl] nvarchar(2048) NOT NULL,
        [IpAddress] nvarchar(45) NULL,
        [Domain] nvarchar(255) NULL,
        [ScanStatus] int NOT NULL,
        [CreatedAt] datetime2 NOT NULL,
        [StartedAt] datetime2 NULL,
        [CompletedAt] datetime2 NULL,
        [UserId] nvarchar(450) NOT NULL,
        CONSTRAINT [PK_ScanTargets] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_ScanTargets_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE NO ACTION
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [DiscoveredServices] (
        [Id] int NOT NULL IDENTITY,
        [ServiceName] nvarchar(100) NOT NULL,
        [Version] nvarchar(100) NOT NULL,
        [Banner] nvarchar(1000) NOT NULL,
        [Port] int NOT NULL,
        [Protocol] nvarchar(10) NOT NULL,
        [RiskLevel] int NOT NULL,
        [ScanTargetId] int NOT NULL,
        CONSTRAINT [PK_DiscoveredServices] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_DiscoveredServices_ScanTargets_ScanTargetId] FOREIGN KEY ([ScanTargetId]) REFERENCES [ScanTargets] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [PortResults] (
        [Id] int NOT NULL IDENTITY,
        [PortNumber] int NOT NULL,
        [Status] int NOT NULL,
        [ServiceName] nvarchar(100) NOT NULL,
        [RiskLevel] int NOT NULL,
        [ScanTargetId] int NOT NULL,
        CONSTRAINT [PK_PortResults] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_PortResults_ScanTargets_ScanTargetId] FOREIGN KEY ([ScanTargetId]) REFERENCES [ScanTargets] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [ScanReports] (
        [Id] int NOT NULL IDENTITY,
        [Title] nvarchar(256) NOT NULL,
        [RiskScore] int NOT NULL,
        [RiskLabel] int NOT NULL,
        [Summary] nvarchar(4000) NOT NULL,
        [GeneratedAt] datetime2 NOT NULL,
        [ScanTargetId] int NOT NULL,
        [UserId] nvarchar(450) NOT NULL,
        CONSTRAINT [PK_ScanReports] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_ScanReports_AspNetUsers_UserId] FOREIGN KEY ([UserId]) REFERENCES [AspNetUsers] ([Id]) ON DELETE NO ACTION,
        CONSTRAINT [FK_ScanReports_ScanTargets_ScanTargetId] FOREIGN KEY ([ScanTargetId]) REFERENCES [ScanTargets] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [Vulnerabilities] (
        [Id] int NOT NULL IDENTITY,
        [Name] nvarchar(256) NOT NULL,
        [Description] nvarchar(2000) NOT NULL,
        [SeverityLevel] int NOT NULL,
        [Category] int NOT NULL,
        [AffectedComponent] nvarchar(500) NOT NULL,
        [Evidence] nvarchar(2000) NOT NULL,
        [DiscoveredAt] datetime2 NOT NULL,
        [ScanTargetId] int NOT NULL,
        CONSTRAINT [PK_Vulnerabilities] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_Vulnerabilities_ScanTargets_ScanTargetId] FOREIGN KEY ([ScanTargetId]) REFERENCES [ScanTargets] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE TABLE [SecurityRecommendations] (
        [Id] int NOT NULL IDENTITY,
        [Title] nvarchar(256) NOT NULL,
        [Description] nvarchar(2000) NOT NULL,
        [Impact] nvarchar(2000) NOT NULL,
        [MitigationSteps] nvarchar(4000) NOT NULL,
        [Priority] int NOT NULL,
        [VulnerabilityId] int NOT NULL,
        CONSTRAINT [PK_SecurityRecommendations] PRIMARY KEY ([Id]),
        CONSTRAINT [FK_SecurityRecommendations_Vulnerabilities_VulnerabilityId] FOREIGN KEY ([VulnerabilityId]) REFERENCES [Vulnerabilities] ([Id]) ON DELETE CASCADE
    );
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    IF EXISTS (SELECT * FROM [sys].[identity_columns] WHERE [name] IN (N'Id', N'ConcurrencyStamp', N'Name', N'NormalizedName') AND [object_id] = OBJECT_ID(N'[AspNetRoles]'))
        SET IDENTITY_INSERT [AspNetRoles] ON;
    EXEC(N'INSERT INTO [AspNetRoles] ([Id], [ConcurrencyStamp], [Name], [NormalizedName])
    VALUES (N''a1b2c3d4-e5f6-7890-abcd-ef1234567890'', N''a1b2c3d4-e5f6-7890-abcd-ef1234567890'', N''Administrator'', N''ADMINISTRATOR''),
    (N''b2c3d4e5-f6a7-8901-bcde-f12345678901'', N''b2c3d4e5-f6a7-8901-bcde-f12345678901'', N''SecurityAnalyst'', N''SECURITYANALYST'')');
    IF EXISTS (SELECT * FROM [sys].[identity_columns] WHERE [name] IN (N'Id', N'ConcurrencyStamp', N'Name', N'NormalizedName') AND [object_id] = OBJECT_ID(N'[AspNetRoles]'))
        SET IDENTITY_INSERT [AspNetRoles] OFF;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AspNetRoleClaims_RoleId] ON [AspNetRoleClaims] ([RoleId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    EXEC(N'CREATE UNIQUE INDEX [RoleNameIndex] ON [AspNetRoles] ([NormalizedName]) WHERE [NormalizedName] IS NOT NULL');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AspNetUserClaims_UserId] ON [AspNetUserClaims] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AspNetUserLogins_UserId] ON [AspNetUserLogins] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AspNetUserRoles_RoleId] ON [AspNetUserRoles] ([RoleId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [EmailIndex] ON [AspNetUsers] ([NormalizedEmail]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    EXEC(N'CREATE UNIQUE INDEX [UserNameIndex] ON [AspNetUsers] ([NormalizedUserName]) WHERE [NormalizedUserName] IS NOT NULL');
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AuditLogs_Timestamp] ON [AuditLogs] ([Timestamp]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_AuditLogs_UserId] ON [AuditLogs] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_DiscoveredServices_ScanTargetId] ON [DiscoveredServices] ([ScanTargetId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_PortResults_ScanTargetId] ON [PortResults] ([ScanTargetId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ScanReports_GeneratedAt] ON [ScanReports] ([GeneratedAt]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_ScanReports_ScanTargetId] ON [ScanReports] ([ScanTargetId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ScanReports_UserId] ON [ScanReports] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ScanTargets_CreatedAt] ON [ScanTargets] ([CreatedAt]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_ScanTargets_UserId] ON [ScanTargets] ([UserId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE UNIQUE INDEX [IX_SecurityRecommendations_VulnerabilityId] ON [SecurityRecommendations] ([VulnerabilityId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Vulnerabilities_ScanTargetId] ON [Vulnerabilities] ([ScanTargetId]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    CREATE INDEX [IX_Vulnerabilities_SeverityLevel] ON [Vulnerabilities] ([SeverityLevel]);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260624031145_InitialCreate'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260624031145_InitialCreate', N'10.0.0');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260705024901_UpdatePendingChanges'
)
BEGIN
    ALTER TABLE [AspNetUsers] ADD [LockoutExpiresAt] datetime2 NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260705024901_UpdatePendingChanges'
)
BEGIN
    ALTER TABLE [AspNetUsers] ADD [LockoutReason] nvarchar(max) NULL;
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260705024901_UpdatePendingChanges'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260705024901_UpdatePendingChanges', N'10.0.0');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260705074442_AddEncryptionForSensitiveData'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260705074442_AddEncryptionForSensitiveData', N'10.0.0');
END;

COMMIT;
GO

BEGIN TRANSACTION;
IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260706140319_AddArchiveSupport'
)
BEGIN
    ALTER TABLE [ScanTargets] ADD [IsArchived] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260706140319_AddArchiveSupport'
)
BEGIN
    ALTER TABLE [ScanReports] ADD [IsArchived] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260706140319_AddArchiveSupport'
)
BEGIN
    ALTER TABLE [AspNetUsers] ADD [IsArchived] bit NOT NULL DEFAULT CAST(0 AS bit);
END;

IF NOT EXISTS (
    SELECT * FROM [__EFMigrationsHistory]
    WHERE [MigrationId] = N'20260706140319_AddArchiveSupport'
)
BEGIN
    INSERT INTO [__EFMigrationsHistory] ([MigrationId], [ProductVersion])
    VALUES (N'20260706140319_AddArchiveSupport', N'10.0.0');
END;

COMMIT;
GO

