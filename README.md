Architecture Overview

Application: VulneraScan ASP.NET Core MVC/Razor application targeting .NET 10

Application Server: Amazon EC2 (Ubuntu Server, t3.micro for the initial project deployment)

Web Server / Reverse Proxy: Nginx

Application Runtime: ASP.NET Core / Kestrel

Database: Amazon RDS for Microsoft SQL Server

Database Connectivity: Private connection from EC2 to RDS on TCP port 1433

Process Management: systemd to keep VulneraScan running and start it automatically

Security: EC2 and RDS Security Groups, HTTPS, protected application secrets

Monitoring: Application logs and AWS monitoring; CloudWatch can be added for centralized logs

System Architecture

The final deployment follows this architecture:

User / Browser
      |
      v
Internet
      |
      v
AWS EC2 Security Group
      |
      v
Nginx (HTTP/HTTPS : 80/443)
      |
      v
ASP.NET Core / Kestrel
VulneraScan (.NET 10)
      |
      | TCP 1433
      v
AWS RDS
Microsoft SQL Server
VulneraScan Database

Important Deployment Principle

Do not deploy the local SQL Server LocalDB configuration to AWS. The production application must connect to the Amazon RDS SQL Server endpoint. The RDS database should not be publicly accessible; only the EC2 application server should be allowed to connect to TCP port 1433.

1. Prepare VulneraScan Locally

Run these commands from the VulneraScan web project folder:

cd C:\Users\ASUS\source\repos\VulneraScan\VulneraScan

dotnet restore

dotnet build

dotnet ef migrations list

The project folder contains VulneraScan.csproj. If dotnet ef is not installed, install it with:

dotnet tool install --global dotnet-ef

2. Launch the AWS EC2 Server

Use the existing EC2 instance for VulneraScan:

Name: VulneraScan-Server

Operating system: Ubuntu Server

Instance type: t3.micro for the initial deployment

Region: US East (N. Virginia), matching the current deployment

Use an EC2 key pair for SSH access

3. Configure the EC2 Security Group

The EC2 Security Group should contain:

Rule

Port

Source

Purpose

SSH

22

My IP

Administrative SSH access

HTTP

80

0.0.0.0/0

Web traffic

HTTPS

443

0.0.0.0/0

Secure web traffic

Do not open SQL Server port 1433 to the public internet. Port 1433 will be configured on the RDS Security Group instead.

4. Create the Amazon RDS SQL Server Database

Open AWS Console → RDS → Databases → Create database.

Choose Microsoft SQL Server.

Use Full configuration so the networking and security settings can be controlled.

Use SQL Server Express if it is available and sufficient for the project workload.

Use a small/free-tier eligible instance class where available, such as db.t3.micro.

DB instance identifier: vulnerascan-db.

Create a strong master username and password. Never commit the password to GitHub.

Keep the RDS database in the same AWS Region and VPC used by the EC2 instance.

Set Public access to No.

Use port 1433.

5. Configure the RDS Security Group

Create or select a dedicated RDS Security Group, for example vulnerascan-db-sg. Its inbound rule should allow SQL Server traffic only from the EC2 application Security Group.

Rule

Port

Source

Purpose

MS SQL Server

1433

EC2 application Security Group

Private database connection

6. Connect to EC2 Through SSH

From the local Windows computer:

ssh -i "vulnerascan-key.pem" ubuntu@YOUR_EC2_PUBLIC_IP

7. Install Required Software on EC2

sudo apt update

sudo apt upgrade -y

sudo apt install -y nginx git curl wget

dotnet --version

Install the .NET 10 SDK/runtime appropriate for the Ubuntu version used by the EC2 instance. Verify the installed version before publishing the application.

8. Upload or Clone VulneraScan

sudo mkdir -p /var/www/vulnerascan

sudo chown ubuntu:ubuntu /var/www/vulnerascan

cd /var/www/vulnerascan

git clone YOUR_GITHUB_REPOSITORY_URL .

dotnet restore

dotnet build

dotnet publish -c Release -o /var/www/vulnerascan/publish

9. Configure the Production Database Connection

The local LocalDB connection must be replaced for production. Use the RDS endpoint supplied by AWS.

Server=YOUR_RDS_ENDPOINT,1433;Database=vulnerascan_db;User Id=YOUR_DB_USER;Password=YOUR_DB_PASSWORD;TrustServerCertificate=True;

Do not place the real password or encryption key in source control. Use protected environment configuration or AWS Secrets Manager for production secrets.

10. Apply EF Core Database Migrations

After the application is configured to point to RDS, apply the existing Entity Framework Core migrations to the production database.

dotnet ef migrations list

dotnet ef database update

Confirm that the migration completes successfully before starting the public application.

11. Configure VulneraScan as a systemd Service

Create a systemd service so the ASP.NET Core application starts automatically and can restart after a failure or server reboot.

/etc/systemd/system/vulnerascan.service

[Unit]
Description=VulneraScan ASP.NET Core Application
After=network.target

[Service]
WorkingDirectory=/var/www/vulnerascan/publish
ExecStart=/usr/bin/dotnet /var/www/vulnerascan/publish/VulneraScan.dll
Restart=always
RestartSec=10
Environment=ASPNETCORE_ENVIRONMENT=Production
User=www-data

[Install]
WantedBy=multi-user.target

sudo systemctl daemon-reload

sudo systemctl enable vulnerascan

sudo systemctl start vulnerascan

sudo systemctl status vulnerascan

12. Configure Nginx as the Reverse Proxy

Edit the Nginx site configuration:

sudo nano /etc/nginx/sites-available/default

Configure Nginx to forward web traffic to the ASP.NET Core/Kestrel application, for example:

server {
    listen 80;
    server_name YOUR_DOMAIN_OR_EC2_IP;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

sudo nginx -t

sudo systemctl restart nginx

13. Test the VulneraScan Deployment

Open the EC2 public IP or configured domain in a browser.

Confirm the VulneraScan login page loads.

Test authentication and authorization.

Test target entry and vulnerability scanning.

Test vulnerability results and recommendations.

Test report generation/download.

Confirm database records are being saved in RDS.

Check application and Nginx logs if an error occurs.

14. Configure HTTPS

After HTTP works correctly, configure a domain and HTTPS. Nginx can terminate HTTPS and forward requests to the local ASP.NET Core application. Do not enable HTTPS troubleshooting before the basic EC2 → Nginx → VulneraScan → RDS path is working.

15. Production Security Checklist

EC2 SSH port 22 is restricted to the administrator's IP where practical.

EC2 exposes only the web ports required for public access.

RDS Public access is disabled.

RDS port 1433 accepts traffic only from the EC2 Security Group.

Production secrets are not committed to GitHub.

Developer exception pages are disabled in production.

ASPNETCORE_ENVIRONMENT is set to Production.

HTTPS is enabled for the public deployment.

Database backups are enabled.

Application logs are monitored.

16. Stop the AWS Resources When Not Presenting

For a student/demo deployment, the EC2 instance can be stopped when the system is not being used. Starting it again later preserves the instance and its attached EBS storage. Compute charges stop while EC2 is stopped, although storage and other AWS resources can still incur charges.

RDS can also be stopped temporarily, but storage and backup charges can remain and an RDS DB instance that is manually stopped has AWS-specific automatic restart behavior. Always verify the current AWS pricing and RDS stop/start rules before relying on stopping the database as a cost-control method.

Do not terminate/delete the EC2 instance or delete the RDS database when you only intend to pause the deployment.

17. Final Deployment Checklist

☐ VulneraScan builds successfully locally

☐ EF Core migrations are available

☐ EC2 VulneraScan-Server is running

☐ EC2 Security Group has SSH/HTTP/HTTPS rules

☐ RDS SQL Server database is created

☐ RDS is in the correct VPC/Region

☐ RDS Public access is No

☐ RDS Security Group allows 1433 only from EC2

☐ VulneraScan is published to EC2

☐ Production connection string points to RDS

☐ EF Core migrations are applied to RDS

☐ systemd service is running

☐ Nginx is running

☐ VulneraScan loads through the browser

☐ Login/scanning/report functions are tested

☐ HTTPS is configured

☐ Backups are enabled

☐ EC2/RDS stop-start procedure is understood for presentations

Deployment Flow Summary

Local VulneraScan
      |
      | Publish
      v
GitHub / Deployment Source
      |
      v
AWS EC2 (Ubuntu)
      |
      +--> Nginx : 80/443
      |
      +--> ASP.NET Core / .NET 10 / Kestrel
                  |
                  | SQL Server : 1433
                  v
          AWS RDS SQL Server
                  |
                  v
          VulneraScan Database
