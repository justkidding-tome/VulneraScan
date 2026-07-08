using Microsoft.EntityFrameworkCore;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using VulneraScan.Data;
using VulneraScan.Models.Enums;
using VulneraScan.Services.Interfaces;

namespace VulneraScan.Services
{
    /// <summary>
    /// Generates professional PDF reports using QuestPDF.
    /// </summary>
    public class PdfReportService : IPdfReportService
    {
        private readonly ApplicationDbContext _context;

        public PdfReportService(ApplicationDbContext context)
        {
            _context = context;
        }

        public async Task<byte[]> GeneratePdfAsync(int reportId)
        {
            QuestPDF.Settings.License = LicenseType.Community;

            var report = await _context.ScanReports
                .Include(r => r.ScanTarget)
                    .ThenInclude(s => s.PortResults)
                .Include(r => r.ScanTarget)
                    .ThenInclude(s => s.DiscoveredServices)
                .Include(r => r.ScanTarget)
                    .ThenInclude(s => s.Vulnerabilities)
                        .ThenInclude(v => v.Recommendation)
                .Include(r => r.User)
                .FirstOrDefaultAsync(r => r.Id == reportId)
                ?? throw new InvalidOperationException($"Report {reportId} not found.");

            var target = report.ScanTarget;
            var vulns = target.Vulnerabilities.ToList();
            var ports = target.PortResults.ToList();
            var services = target.DiscoveredServices.ToList();

            var document = Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Size(PageSizes.A4);
                    page.Margin(40);
                    page.DefaultTextStyle(x => x.FontSize(10));

                    // Header
                    page.Header().Column(col =>
                    {
                        col.Item().Row(row =>
                        {
                            row.RelativeItem().Column(c =>
                            {
                                c.Item().Text("VulneraScan").FontSize(22).Bold().FontColor(Colors.Blue.Darken3);
                                c.Item().Text("Vulnerability Assessment Report").FontSize(14).FontColor(Colors.Grey.Darken1);
                            });
                            row.ConstantItem(120).AlignRight().Column(c =>
                            {
                                c.Item().Text($"Date: {report.GeneratedAt:yyyy-MM-dd}").FontSize(9);
                                c.Item().Text($"Report ID: {report.Id}").FontSize(9);
                            });
                        });
                        col.Item().PaddingTop(5).LineHorizontal(2).LineColor(Colors.Blue.Darken3);
                    });

                    // Content
                    page.Content().PaddingVertical(10).Column(col =>
                    {
                        // Target Information
                        col.Item().PaddingBottom(10).Column(section =>
                        {
                            section.Item().Text("Target Information").FontSize(14).Bold().FontColor(Colors.Blue.Darken2);
                            section.Item().PaddingTop(5).Table(table =>
                            {
                                table.ColumnsDefinition(c =>
                                {
                                    c.ConstantColumn(120);
                                    c.RelativeColumn();
                                });
                                AddTableRow(table, "Target URL", target.TargetUrl);
                                AddTableRow(table, "IP Address", target.IpAddress ?? "N/A");
                                AddTableRow(table, "Domain", target.Domain ?? "N/A");
                                AddTableRow(table, "Scan Started", target.StartedAt?.ToString("yyyy-MM-dd HH:mm:ss UTC") ?? "N/A");
                                AddTableRow(table, "Scan Completed", target.CompletedAt?.ToString("yyyy-MM-dd HH:mm:ss UTC") ?? "N/A");
                                if (target.StartedAt.HasValue && target.CompletedAt.HasValue)
                                {
                                    var duration = target.CompletedAt.Value - target.StartedAt.Value;
                                    AddTableRow(table, "Duration", $"{duration.TotalSeconds:F1} seconds");
                                }
                            });
                        });

                        // Risk Score
                        col.Item().PaddingBottom(10).Column(section =>
                        {
                            section.Item().Text("Risk Assessment").FontSize(14).Bold().FontColor(Colors.Blue.Darken2);
                            section.Item().PaddingTop(5).Row(row =>
                            {
                                var riskColor = report.RiskLabel switch
                                {
                                    RiskLabel.High => Colors.Red.Darken1,
                                    RiskLabel.Medium => Colors.Orange.Darken1,
                                    RiskLabel.Low => Colors.Yellow.Darken2,
                                    _ => Colors.Green.Darken1
                                };

                                row.ConstantItem(100).Height(50).Background(riskColor).AlignCenter().AlignMiddle()
                                    .Text($"{report.RiskLabel}").FontSize(16).Bold().FontColor(Colors.White);
                                row.RelativeItem().PaddingLeft(10).AlignMiddle()
                                    .Text($"Risk Score: {report.RiskScore}  |  {vulns.Count} Vulnerabilities Found").FontSize(12);
                            });
                        });

                        // Severity Breakdown
                        col.Item().PaddingBottom(10).Column(section =>
                        {
                            section.Item().Text("Severity Breakdown").FontSize(14).Bold().FontColor(Colors.Blue.Darken2);
                            section.Item().PaddingTop(5).Row(row =>
                            {
                                var highCount = vulns.Count(v => v.SeverityLevel == SeverityLevel.High);
                                var medCount = vulns.Count(v => v.SeverityLevel == SeverityLevel.Medium);
                                var lowCount = vulns.Count(v => v.SeverityLevel == SeverityLevel.Low);

                                AddSeverityBox(row, "HIGH", highCount, Colors.Red.Darken1);
                                AddSeverityBox(row, "MEDIUM", medCount, Colors.Orange.Darken1);
                                AddSeverityBox(row, "LOW", lowCount, Colors.Yellow.Darken2);
                            });
                        });

                        // Port Scan Results
                        if (ports.Count != 0)
                        {
                            col.Item().PaddingBottom(10).Column(section =>
                            {
                                section.Item().Text("Port Scan Results").FontSize(14).Bold().FontColor(Colors.Blue.Darken2);
                                section.Item().PaddingTop(5).Table(table =>
                                {
                                    table.ColumnsDefinition(c =>
                                    {
                                        c.ConstantColumn(60);
                                        c.RelativeColumn();
                                        c.ConstantColumn(80);
                                        c.ConstantColumn(80);
                                    });
                                    table.Header(h =>
                                    {
                                        h.Cell().Background(Colors.Grey.Lighten2).Padding(4).Text("Port").Bold();
                                        h.Cell().Background(Colors.Grey.Lighten2).Padding(4).Text("Service").Bold();
                                        h.Cell().Background(Colors.Grey.Lighten2).Padding(4).Text("Status").Bold();
                                        h.Cell().Background(Colors.Grey.Lighten2).Padding(4).Text("Risk").Bold();
                                    });
                                    foreach (var p in ports.OrderBy(p => p.PortNumber))
                                    {
                                        table.Cell().Padding(3).Text(p.PortNumber.ToString());
                                        table.Cell().Padding(3).Text(p.ServiceName);
                                        table.Cell().Padding(3).Text(p.Status.ToString());
                                        table.Cell().Padding(3).Text(p.Status == PortStatus.Open ? p.RiskLevel.ToString() : "-");
                                    }
                                });
                            });
                        }

                        // Vulnerability Findings
                        if (vulns.Count != 0)
                        {
                            col.Item().PaddingBottom(10).Column(section =>
                            {
                                section.Item().Text("Vulnerability Findings").FontSize(14).Bold().FontColor(Colors.Blue.Darken2);
                                foreach (var vuln in vulns.OrderByDescending(v => v.SeverityLevel))
                                {
                                    var sevColor = vuln.SeverityLevel switch
                                    {
                                        SeverityLevel.High => Colors.Red.Lighten4,
                                        SeverityLevel.Medium => Colors.Orange.Lighten4,
                                        _ => Colors.Yellow.Lighten4
                                    };

                                    section.Item().PaddingTop(5).Border(1).BorderColor(Colors.Grey.Lighten1).Column(vulnBox =>
                                    {
                                        vulnBox.Item().Background(sevColor).Padding(5).Row(r =>
                                        {
                                            r.RelativeItem().Text(vuln.Name).Bold();
                                            r.ConstantItem(60).AlignRight().Text(vuln.SeverityLevel.ToString()).Bold();
                                        });
                                        vulnBox.Item().Padding(5).Column(detail =>
                                        {
                                            detail.Item().Text(vuln.Description).FontSize(9);
                                            detail.Item().PaddingTop(3).Text($"Category: {vuln.Category}").FontSize(9).Italic();
                                            detail.Item().Text($"Component: {vuln.AffectedComponent}").FontSize(9).Italic();
                                            if (!string.IsNullOrEmpty(vuln.Evidence))
                                                detail.Item().PaddingTop(3).Text($"Evidence: {vuln.Evidence}").FontSize(8).FontColor(Colors.Grey.Darken1);

                                            if (vuln.Recommendation != null)
                                            {
                                                detail.Item().PaddingTop(5).Text("Recommendation:").FontSize(9).Bold();
                                                detail.Item().Text(vuln.Recommendation.MitigationSteps).FontSize(8);
                                            }
                                        });
                                    });
                                }
                            });
                        }

                        // Summary
                        col.Item().PaddingTop(10).Column(section =>
                        {
                            section.Item().Text("Summary").FontSize(14).Bold().FontColor(Colors.Blue.Darken2);
                            section.Item().PaddingTop(5).Text(report.Summary).FontSize(10);
                        });
                    });

                    // Footer
                    page.Footer().AlignCenter().Text(text =>
                    {
                        text.Span("VulneraScan Report  |  Page ");
                        text.CurrentPageNumber();
                        text.Span(" of ");
                        text.TotalPages();
                        text.Span($"  |  Generated: {report.GeneratedAt:yyyy-MM-dd HH:mm:ss UTC}");
                    });
                });
            });

            return document.GeneratePdf();
        }

        private static void AddTableRow(TableDescriptor table, string label, string value)
        {
            table.Cell().Padding(3).Text(label).Bold().FontSize(9);
            table.Cell().Padding(3).Text(value).FontSize(9);
        }

        private static void AddSeverityBox(RowDescriptor row, string label, int count, string color)
        {
            row.RelativeItem().Padding(5).Background(color).Padding(10).AlignCenter().Column(c =>
            {
                c.Item().AlignCenter().Text(count.ToString()).FontSize(18).Bold().FontColor(Colors.White);
                c.Item().AlignCenter().Text(label).FontSize(10).FontColor(Colors.White);
            });
        }
    }
}
