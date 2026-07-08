using VulneraScan.Models;

namespace VulneraScan.Services.Interfaces
{
    /// <summary>
    /// Generates security recommendations for detected vulnerabilities.
    /// </summary>
    public interface IRecommendationService
    {
        List<SecurityRecommendation> GenerateRecommendations(IEnumerable<Vulnerability> vulnerabilities);
    }
}
