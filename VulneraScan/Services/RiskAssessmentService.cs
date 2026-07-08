using VulneraScan.Helpers;
using VulneraScan.Models;
using VulneraScan.Models.Enums;
using VulneraScan.Services.Interfaces;

namespace VulneraScan.Services
{
    /// <summary>
    /// Calculates aggregate risk scores and labels from vulnerability findings.
    /// </summary>
    public class RiskAssessmentService : IRiskAssessmentService
    {
        public (int Score, RiskLabel Label) CalculateRisk(IEnumerable<Vulnerability> vulnerabilities)
        {
            var score = vulnerabilities.Sum(v => (int)v.SeverityLevel);
            var label = GetRiskLabel(score);
            return (score, label);
        }

        private static RiskLabel GetRiskLabel(int score)
        {
            if (score <= Constants.RiskScoring.MinimalMax)
                return RiskLabel.Minimal;
            if (score <= Constants.RiskScoring.LowMax)
                return RiskLabel.Low;
            if (score <= Constants.RiskScoring.MediumMax)
                return RiskLabel.Medium;
            return RiskLabel.High;
        }
    }
}
