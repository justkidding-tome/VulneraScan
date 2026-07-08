using VulneraScan.Models;
using VulneraScan.Models.Enums;

namespace VulneraScan.Services.Interfaces
{
    /// <summary>
    /// Calculates risk scores and labels from vulnerability findings.
    /// </summary>
    public interface IRiskAssessmentService
    {
        (int Score, RiskLabel Label) CalculateRisk(IEnumerable<Vulnerability> vulnerabilities);
    }
}
